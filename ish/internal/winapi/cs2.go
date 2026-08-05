//go:build windows
// +build windows

package winapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"scanner/internal/models"
)

const (
	cs2ProcessQueryInfo = 0x0400 // PROCESS_QUERY_INFORMATION
	cs2ProcessVMRead    = 0x0010 // PROCESS_VM_READ

	cs2MemCommit       = 0x1000
	cs2PageExecuteRW   = 0x40 // PAGE_EXECUTE_READWRITE
	cs2PageExecuteWC   = 0x80 // PAGE_EXECUTE_WRITECOPY

	cs2TCPTableOwnerPidAll = 5
	cs2AFInet              = 2  // AF_INET
	cs2AFInet6             = 23 // AF_INET6
)

type cs2MibTcpRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type cs2MibTcp6RowOwnerPid struct {
	LocalAddr     [16]byte
	LocalScopeId  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeId uint32
	RemotePort    uint32
	State         uint32
	OwningPid     uint32
}

// FindCS2PID returns the PID of cs2.exe, or 0 if it is not running.
func FindCS2PID() uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "cs2.exe") {
			return entry.ProcessID
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0
}

// GetCS2Connections enumerates TCP connections (IPv4 + IPv6) owned by the
// given PID. Only connections with a non-zero remote address are returned
// (i.e. established / connecting sockets — not LISTEN).
func GetCS2Connections(pid uint32) []models.CS2Connection {
	var conns []models.CS2Connection
	if v4 := cs2GetTCPv4Connections(pid); len(v4) > 0 {
		conns = append(conns, v4...)
	}
	if v6 := cs2GetTCPv6Connections(pid); len(v6) > 0 {
		conns = append(conns, v6...)
	}
	return conns
}

func cs2GetTCPv4Connections(pid uint32) []models.CS2Connection {
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	proc := iphlpapi.NewProc("GetExtendedTcpTable")

	var size uint32
	r1, _, _ := proc.Call(
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		1, // AF_INET
		cs2TCPTableOwnerPidAll,
		0,
	)
	if r1 != 0 && r1 != 122 { // 122 = ERROR_INSUFFICIENT_BUFFER
		return nil
	}
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	r2, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		1,
		cs2TCPTableOwnerPidAll,
		0,
	)
	if r2 != 0 {
		return nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(cs2MibTcpRowOwnerPid{}))
	var out []models.CS2Connection
	for i := uint32(0); i < numEntries; i++ {
		off := 4 + i*rowSize
		if int(off)+int(rowSize) > len(buf) {
			break
		}
		row := (*cs2MibTcpRowOwnerPid)(unsafe.Pointer(&buf[off]))
		if row.OwningPid != pid {
			continue
		}
		if row.RemoteAddr == 0 && row.RemotePort == 0 {
			continue // LISTEN / no remote endpoint
		}
		out = append(out, models.CS2Connection{
			LocalAddress:  cs2IPv4String(row.LocalAddr),
			LocalPort:     cs2NtohsPort(row.LocalPort),
			RemoteAddress: cs2IPv4String(row.RemoteAddr),
			RemotePort:    cs2NtohsPort(row.RemotePort),
			State:         cs2TCPStateName(row.State),
		})
	}
	return out
}

func cs2GetTCPv6Connections(pid uint32) []models.CS2Connection {
	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	proc := iphlpapi.NewProc("GetExtendedTcpTable")

	var size uint32
	r1, _, _ := proc.Call(
		0, 0,
		uintptr(unsafe.Pointer(&size)),
		cs2AFInet6,
		cs2TCPTableOwnerPidAll,
		0,
	)
	if r1 != 0 && r1 != 122 {
		return nil
	}
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	r2, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		cs2AFInet6,
		cs2TCPTableOwnerPidAll,
		0,
	)
	if r2 != 0 {
		return nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(cs2MibTcp6RowOwnerPid{}))
	var out []models.CS2Connection
	for i := uint32(0); i < numEntries; i++ {
		off := 4 + i*rowSize
		if int(off)+int(rowSize) > len(buf) {
			break
		}
		row := (*cs2MibTcp6RowOwnerPid)(unsafe.Pointer(&buf[off]))
		if row.OwningPid != pid {
			continue
		}
		if cs2IsZeroIPv6(row.RemoteAddr) {
			continue
		}
		out = append(out, models.CS2Connection{
			LocalAddress:  net.IP(row.LocalAddr[:]).String(),
			LocalPort:     cs2NtohsPort(row.LocalPort),
			RemoteAddress: net.IP(row.RemoteAddr[:]).String(),
			RemotePort:    cs2NtohsPort(row.RemotePort),
			State:         cs2TCPStateName(row.State),
		})
	}
	return out
}

// GetCS2RWXRegions walks cs2.exe's virtual address space with VirtualQueryEx
// and returns every committed region whose protection includes executable +
// write (PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY). These are the
// classic "RWX in executable pages" indicators of injected cheats.
func GetCS2RWXRegions(pid uint32) ([]models.CS2RWXRegion, error) {
	h, err := windows.OpenProcess(cs2ProcessQueryInfo|cs2ProcessVMRead, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer windows.CloseHandle(h)

	var regions []models.CS2RWXRegion
	var mbi windows.MemoryBasicInformation
	mbiSize := uintptr(unsafe.Sizeof(mbi))
	var addr uintptr

	for {
		err := windows.VirtualQueryEx(h, addr, &mbi, mbiSize)
		if err != nil {
			break
		}
		if mbi.RegionSize == 0 {
			break
		}
		if mbi.State == cs2MemCommit && (mbi.Protect == cs2PageExecuteRW || mbi.Protect == cs2PageExecuteWC) {
			regions = append(regions, models.CS2RWXRegion{
				BaseAddress: mbi.BaseAddress,
				RegionSize:  mbi.RegionSize,
				Protection:  cs2ProtectName(mbi.Protect),
				RegionType:  cs2MemTypeName(mbi.Type),
			})
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return regions, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────

func cs2NtohsPort(v uint32) int {
	// Port is stored in the upper 16 bits in network byte order.
	raw := uint16(v >> 16)
	return int((raw << 8) | (raw >> 8))
}

func cs2IPv4String(addr uint32) string {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

func cs2IsZeroIPv6(a [16]byte) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}

func cs2TCPStateName(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT_1"
	case 7:
		return "FIN_WAIT_2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE(%d)", state)
	}
}

func cs2ProtectName(p uint32) string {
	switch p {
	case cs2PageExecuteRW:
		return "PAGE_EXECUTE_READWRITE"
	case cs2PageExecuteWC:
		return "PAGE_EXECUTE_WRITECOPY"
	default:
		return fmt.Sprintf("0x%x", p)
	}
}

func cs2MemTypeName(t uint32) string {
	switch t {
	case 0x20000:
		return "MEM_PRIVATE"
	case 0x40000:
		return "MEM_MAPPED"
	case 0x1000000:
		return "MEM_IMAGE"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}
