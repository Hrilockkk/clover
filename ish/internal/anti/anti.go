//go:build windows
// +build windows

// Package anti implements hardening checks for the Clover scanner: anti-debugging,
// anti-VM/sandbox and timing anomalies. It is intentionally limited to
// user-mode checks and does not disable security software or use kernel-level
// tricks.
package anti

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"scanner/internal/logger"
	"scanner/internal/obfuscate"
	"scanner/internal/winapi"
)

// RunHardening executes all hardening checks. If anything suspicious is
// detected, the process exits after logging the reason.
func RunHardening() {
	if winapi.ProtectionBypassAllowed() {
		return
	}
	if winapi.IsDebuggerPresent() {
		logger.Warn("debugger detected, exiting")
		os.Exit(1)
	}
	if analysisEnvironment() {
		logger.Warn("analysis/VM/sandbox environment detected, exiting")
		os.Exit(1)
	}
	if timingAnomaly() {
		logger.Warn("timing anomaly detected, exiting")
		os.Exit(1)
	}
	if currentProcessAnomaly() {
		logger.Warn("process name anomaly detected, exiting")
		os.Exit(1)
	}
}

// analysisEnvironment returns true if the process appears to be running inside a
// VM, sandbox, or analysis harness.
func analysisEnvironment() bool {
	// Registry-based VM detection.
	if checkVMRegistry() {
		return true
	}
	// Driver-based VM detection.
	if checkVMDrivers() {
		return true
	}
	// Sandboxie / similar DLL injection.
	if checkSandboxDLL() {
		return true
	}
	return false
}

func checkVMRegistry() bool {
	keys := []struct {
		root  registry.Key
		path  string
		value string
	}{
		{registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, `SystemBiosVersion`},
		{registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System`, `VideoBiosVersion`},
		{registry.LOCAL_MACHINE, `HARDWARE\ACPI\DSDT`, ``},
		{registry.LOCAL_MACHINE, `HARDWARE\ACPI\FADT`, ``},
	}
	vmTokens := []string{
		`VMWARE`, `VBOX`, `VIRTUAL`, `QEMU`, `XEN`, `PARALLELS`, `HYPER-V`, `BOCHS`, `INSIDE`, `SANDCASTLE`,
	}
	for _, k := range keys {
		var text string
		if k.value == `` {
			// Enumerate subkeys and check names.
			key, err := registry.OpenKey(k.root, k.path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			names, err := key.ReadSubKeyNames(0)
			key.Close()
			if err != nil {
				continue
			}
			for _, name := range names {
				text += name + "\n"
			}
		} else {
			key, err := registry.OpenKey(k.root, k.path, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			val, _, err := key.GetStringValue(k.value)
			key.Close()
			if err != nil {
				continue
			}
			text = val
		}
		upper := strings.ToUpper(text)
		for _, token := range vmTokens {
			if strings.Contains(upper, token) {
				return true
			}
		}
	}
	return false
}

func checkVMDrivers() bool {
	drivers := []string{
		`C:\Windows\System32\drivers\vmci.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vmmemctl.sys`,
		`C:\Windows\System32\drivers\vmrawdsk.sys`,
		`C:\Windows\System32\drivers\vboxguest.sys`,
		`C:\Windows\System32\drivers\vboxmouse.sys`,
		`C:\Windows\System32\drivers\vboxsf.sys`,
		`C:\Windows\System32\drivers\vboxvideo.sys`,
	}
	for _, d := range drivers {
		if _, err := os.Stat(d); err == nil {
			return true
		}
	}
	return false
}

func checkSandboxDLL() bool {
	modules := []string{
		`SbieDll.dll`,
		`SxIn.dll`,
		`api_log.dll`,
		`dir_watch.dll`,
	}
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}
	var mods [1024]windows.Handle
	var needed uint32
	if err := windows.EnumProcessModules(h, &mods[0], uint32(len(mods)*int(unsafe.Sizeof(mods[0]))), &needed); err != nil {
		return false
	}
	count := int(needed) / int(unsafe.Sizeof(mods[0]))
	if count > len(mods) {
		count = len(mods)
	}
	buf := make([]uint16, 512)
	for i := 0; i < count; i++ {
		if err := windows.GetModuleBaseName(h, mods[i], &buf[0], uint32(len(buf))); err != nil {
			continue
		}
		name := windows.UTF16ToString(buf)
		upper := strings.ToUpper(name)
		for _, mod := range modules {
			if upper == strings.ToUpper(mod) {
				return true
			}
		}
	}
	return false
}

// timingAnomaly returns true if the execution time of a tight loop is
// suspiciously high, which often indicates single-stepping under a debugger.
func timingAnomaly() bool {
	const threshold = 100 * time.Millisecond
	start := qpc()
	sum := 0
	for i := 0; i < 100000; i++ {
		sum += i
	}
	if sum == 0 {
		return true
	}
	elapsed := qpc() - start
	return elapsed > threshold
}

func qpc() time.Duration {
	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	qpc := kernel32.NewProc(`QueryPerformanceCounter`)
	var now int64
	qpc.Call(uintptr(unsafe.Pointer(&now)))
	freq := qpf()
	if freq == 0 {
		return time.Duration(now) * time.Nanosecond
	}
	return time.Duration(now) * time.Second / time.Duration(freq)
}

func qpf() int64 {
	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	qpf := kernel32.NewProc(`QueryPerformanceFrequency`)
	var freq int64
	qpf.Call(uintptr(unsafe.Pointer(&freq)))
	return freq
}

// currentProcessAnomaly checks whether the running executable has been renamed
// to a common debugger or analysis tool, which is a trivial sandbox/VM trick.
func currentProcessAnomaly() bool {
	suspicious := []string{
		`x64dbg`, `x32dbg`, `ollydbg`, `windbg`, `idaq`, `idag`, `idaw`, `ida64`,
		`immunity`, `decompile`, `ghidra`, `dnspy`, `cheatengine`, `cheat engine`,
		`processhacker`, `procmon`, `procexp`, `tcpview`, `wireshark`, `fiddler`,
	}
	h, err := windows.GetCurrentProcess()
	if err != nil {
		return false
	}
	buf := make([]uint16, 512)
	if err := windows.GetModuleBaseName(h, 0, &buf[0], uint32(len(buf))); err != nil {
		return false
	}
	exeName := strings.ToUpper(windows.UTF16ToString(buf))
	for _, n := range suspicious {
		if strings.Contains(exeName, strings.ToUpper(n)) {
			return true
		}
	}
	return false
}

// StripZoneIdentifier removes the "Mark of the Web" ADS from the executable so
// that downloaded builds do not carry an internet-zone reputation flag.
func StripZoneIdentifier(exePath string) error {
	adsPath := exePath + `:Zone.Identifier`
	return os.Remove(adsPath)
}

// RandomExeName returns a random-looking filename in %TEMP% so that the
// downloaded scanner does not appear as a known binary in security reputation
// databases.
func RandomExeName() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// fallback to timestamp-based name
		return `cl_` + time.Now().Format(`150405`) + `.exe`
	}
	return `cl_` + hex.EncodeToString(b) + `.exe`
}

// TempPath returns the value of %TEMP% with a trailing separator.
func TempPath() string {
	temp := os.Getenv(`TEMP`)
	if temp == `` {
		temp = os.Getenv(`TMP`)
	}
	if temp == `` {
		temp = `C:\Temp`
	}
	return filepath.Join(temp, ``) + string(filepath.Separator)
}

// HideWindow configures a SysProcAttr to create a hidden console window.
func HideWindow() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
}
