//go:build !windows
// +build !windows

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("This scanner is Windows-only.")
	os.Exit(1)
}
