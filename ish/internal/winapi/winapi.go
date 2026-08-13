//go:build windows
// +build windows

package winapi

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"scanner/internal/obfuscate"
)

const (
	ProcessDebugPort         = uint32(7)
	ProcessDebugObjectHandle = uint32(30)
	NtStatusSuccess          = uintptr(0)
)

func EnableConsoleVT() {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

func ProtectionBypassAllowed() bool {
	return strings.TrimSpace(os.Getenv("SCANNER_ALLOW_DEBUG")) == "1"
}

func IsDebuggerPresent() bool {
	if ProtectionBypassAllowed() {
		return false
	}
	if kernel32DebuggerChecks() {
		return true
	}
	if ntdllDebuggerChecks() {
		return true
	}
	return false
}

func kernel32DebuggerChecks() bool {
	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	isDbg := kernel32.NewProc(obfuscate.IS_DEBUGGER_PRESENT())
	r1, _, _ := isDbg.Call()
	if r1 != 0 {
		return true
	}
	checkRemote := kernel32.NewProc(obfuscate.CHECK_REMOTE_DEBUGGER())
	getCurrentProcess := kernel32.NewProc(obfuscate.GET_CURRENT_PROCESS())
	h, _, _ := getCurrentProcess.Call()
	var present uint32
	r2, _, _ := checkRemote.Call(h, uintptr(unsafe.Pointer(&present)))
	return r2 != 0 && present != 0
}

func ntdllDebuggerChecks() bool {
	ntdll := windows.NewLazySystemDLL(obfuscate.NTDLL())
	q := ntdll.NewProc(obfuscate.NT_QUERY_INFO_PROCESS())
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}

	var debugPort uintptr
	r, _, _ := q.Call(
		uintptr(h),
		uintptr(ProcessDebugPort),
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		0,
	)
	if r == NtStatusSuccess && debugPort != 0 {
		return true
	}

	var debugObj uintptr
	r2, _, _ := q.Call(
		uintptr(h),
		uintptr(ProcessDebugObjectHandle),
		uintptr(unsafe.Pointer(&debugObj)),
		unsafe.Sizeof(debugObj),
		0,
	)
	return r2 == NtStatusSuccess && debugObj != 0
}

func FiletimeToTime(ft windows.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
}

func GetSystemBootTime() time.Time {
	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	getTickCount64 := kernel32.NewProc("GetTickCount64")
	uptimeMs, _, _ := getTickCount64.Call()
	return time.Now().Add(-time.Duration(uptimeMs) * time.Millisecond)
}

func GetDrives() []string {
	var drives []string
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		fmt.Printf("[ERROR] GetLogicalDrives failed: %v\n", err)
		return drives
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			letter := string(rune('A' + i))
			root := letter + ":\\"
			ptr, err := windows.UTF16PtrFromString(root)
			if err != nil {
				continue
			}
			driveType := windows.GetDriveType(ptr)
			var typeName string
			switch driveType {
			case windows.DRIVE_FIXED:
				typeName = "FIXED"
			case windows.DRIVE_REMOVABLE:
				typeName = "REMOVABLE"
			case windows.DRIVE_REMOTE:
				typeName = "REMOTE"
			case windows.DRIVE_RAMDISK:
				typeName = "RAMDISK"
			case windows.DRIVE_CDROM:
				typeName = "CDROM"
			case windows.DRIVE_UNKNOWN:
				typeName = "UNKNOWN"
			default:
				typeName = fmt.Sprintf("TYPE(%d)", driveType)
			}
			switch driveType {
			case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK:
				fmt.Printf("[DRIVE] %s: %s\n", letter, typeName)
				drives = append(drives, strings.TrimSuffix(root, "\\"))
			default:
				// REMOTE is excluded on purpose: raw MFT/USN do not work on
				// network shares, and a full filesystem walk over SMB can take
				// hours.
				fmt.Printf("[SKIP]  %s: %s (unsupported)\n", letter, typeName)
			}
		}
	}
	return drives
}

func OpenVolumeHandle(drive string) (windows.Handle, error) {
	volumePath, err := windows.UTF16PtrFromString(`\\.\` + drive)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(
		volumePath,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	return h, nil
}

func DeviceIoControl(handle windows.Handle, code uint32, inBuf unsafe.Pointer, inSize uint32, outBuf unsafe.Pointer, outSize uint32, returned *uint32) error {
	var inPtr *byte
	var outPtr *byte
	if inBuf != nil && inSize > 0 {
		inPtr = (*byte)(inBuf)
	}
	if outBuf != nil && outSize > 0 {
		outPtr = (*byte)(outBuf)
	}
	return windows.DeviceIoControl(handle, code, inPtr, inSize, outPtr, outSize, returned, nil)
}

// IsReparsePoint reports whether a directory entry is a junction/symlink.
// Filesystem walks must skip these, otherwise junction cycles (e.g.
// "AppData\Local\Application Data" -> itself) cause infinite recursion.
// DirEntry.Info() on Windows reuses the FindFirstFile data — no extra syscall.
func IsReparsePoint(entry os.DirEntry) bool {
	info, err := entry.Info()
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*windows.Win32FileAttributeData)
	if !ok {
		return false
	}
	return stat.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func WinAttrsToString(path string) string {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "UNKNOWN"
	}
	attr, err := windows.GetFileAttributes(ptr)
	if err != nil {
		return "UNKNOWN"
	}

	var out []string
	add := func(flag uint32, name string) {
		if attr&flag != 0 {
			out = append(out, name)
		}
	}

	add(windows.FILE_ATTRIBUTE_DIRECTORY, "DIR")
	add(windows.FILE_ATTRIBUTE_READONLY, "READONLY")
	add(windows.FILE_ATTRIBUTE_HIDDEN, "HIDDEN")
	add(windows.FILE_ATTRIBUTE_SYSTEM, "SYSTEM")
	add(windows.FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE")
	add(windows.FILE_ATTRIBUTE_REPARSE_POINT, "REPARSE")
	add(windows.FILE_ATTRIBUTE_COMPRESSED, "COMPRESSED")
	add(windows.FILE_ATTRIBUTE_ENCRYPTED, "ENCRYPTED")
	add(windows.FILE_ATTRIBUTE_TEMPORARY, "TEMPORARY")
	add(windows.FILE_ATTRIBUTE_OFFLINE, "OFFLINE")
	add(windows.FILE_ATTRIBUTE_INTEGRITY_STREAM, "INTEGRITY")
	add(windows.FILE_ATTRIBUTE_NO_SCRUB_DATA, "NO_SCRUB")

	if len(out) == 0 {
		return "NORMAL"
	}
	return strings.Join(out, "|")
}
