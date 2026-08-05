//go:build windows
// +build windows

package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	Reset   = "\x1b[0m"
	Bold    = "\x1b[1m"
	Cyan    = "\x1b[36m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	White   = "\x1b[37m"
	Magenta = "\x1b[35m"
	Red     = "\x1b[31m"
	Gray    = "\x1b[90m"
)

// ShowMenu displays a compact 80-column post-scan menu.
func ShowMenu() int {
	fmt.Println()
	fmt.Println(Cyan + "┌─ Actions ──────────────────────────────────────────────────────────────┐" + Reset)
	fmt.Println(Cyan + "│" + Reset + "  [1] " + Green + "Save JSON + self-destruct" + Reset + strings.Repeat(" ", 46) + Cyan + "│" + Reset)
	fmt.Println(Cyan + "│" + Reset + "  [2] " + Yellow + "Save console report     " + Reset + strings.Repeat(" ", 49) + Cyan + "│" + Reset)
	fmt.Println(Cyan + "└────────────────────────────────────────────────────────────────────────┘" + Reset)
	fmt.Println()

	for {
		fmt.Print(White + "  Select [1/2]: " + Reset)
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "1" || text == "2" {
			fmt.Println()
			return int(text[0] - '0')
		}
		fmt.Println(Red + "  Invalid choice." + Reset)
	}
}
