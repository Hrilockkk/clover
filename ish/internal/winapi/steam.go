//go:build windows
// +build windows

package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
	"scanner/internal/models"
)

// CollectSteam reads the registry and VDF files to extract all Steam accounts
// and library paths. Returns a populated SteamInfo.
func CollectSteam() (*models.SteamInfo, error) {
	info := &models.SteamInfo{}

	// 1. Registry: HKCU\Software\Valve\Steam
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Valve\Steam`, registry.QUERY_VALUE)
	if err != nil {
		return info, fmt.Errorf("steam registry: %w", err)
	}
	defer k.Close()

	steamPath, _, _ := k.GetStringValue("SteamPath")
	if steamPath == "" {
		steamPath, _, _ = k.GetStringValue("SteamExe")
		steamPath = filepath.Dir(steamPath)
	}
	if steamPath != "" {
		steamPath = strings.ReplaceAll(steamPath, "/", string(filepath.Separator))
	}
	info.SteamPath = steamPath

	if steamPath == "" {
		return info, fmt.Errorf("steam path not found")
	}

	// 2. Parse loginusers.vdf
	loginusersPath := filepath.Join(steamPath, "config", "loginusers.vdf")
	if data, err := os.ReadFile(loginusersPath); err == nil {
		info.Accounts = parseLoginUsers(data)
	}

	// 3. Parse libraryfolders.vdf
	libraryPath := filepath.Join(steamPath, "steamapps", "libraryfolders.vdf")
	if data, err := os.ReadFile(libraryPath); err == nil {
		info.LibraryPaths = parseLibraryFolders(data)
	}

	// Always include the main steam path as a library
	if len(info.LibraryPaths) == 0 {
		info.LibraryPaths = []string{steamPath}
	}

	return info, nil
}

// parseLoginUsers parses loginusers.vdf and extracts all Steam accounts.
// Format:
//   "users"
//   {
//     "765611980..."
//     {
//       "Account"     "username"
//       "SteamID"     "765611980..."
//       "MostRecent"  "1"
//       "Timestamp"   "1234567890"
//     }
//   }
func parseLoginUsers(data []byte) []models.SteamAccount {
	var accounts []models.SteamAccount
	tokens := vdfTokenize(data)
	// Find "users" block
	i := 0
	for i < len(tokens) {
		if tokens[i] == "users" && i+1 < len(tokens) && tokens[i+1] == "{" {
			i += 2
			break
		}
		i++
	}

	// Iterate: steamID { key value key value ... }
	for i < len(tokens) {
		if tokens[i] == "}" {
			break
		}
		steamID := tokens[i]
		i++
		if i >= len(tokens) || tokens[i] != "{" {
			continue
		}
		i++
		acct := models.SteamAccount{SteamID: steamID}
		for i < len(tokens) && tokens[i] != "}" {
			key := tokens[i]
			i++
			if i >= len(tokens) {
				break
			}
			val := tokens[i]
			i++
			switch key {
			case "Account":
				acct.AccountName = val
			case "MostRecent":
				acct.MostRecent = val == "1"
			case "Timestamp":
				if ts, err := strconv.ParseInt(val, 10, 64); err == nil {
					acct.Timestamp = fmt.Sprintf("%d", ts)
				}
			}
		}
		if i < len(tokens) && tokens[i] == "}" {
			i++
		}
		accounts = append(accounts, acct)
	}
	return accounts
}

// parseLibraryFolders parses libraryfolders.vdf and extracts all library paths.
// Format:
//   "libraryfolders"
//   {
//     "0" { "path" "C:\\Steam" ... }
//     "1" { "path" "D:\\SteamLibrary" ... }
//   }
func parseLibraryFolders(data []byte) []string {
	var paths []string
	tokens := vdfTokenize(data)
	i := 0
	for i < len(tokens) {
		if tokens[i] == "libraryfolders" && i+1 < len(tokens) && tokens[i+1] == "{" {
			i += 2
			break
		}
		i++
	}

	for i < len(tokens) {
		if tokens[i] == "}" {
			break
		}
		// Skip the index number
		i++
		if i >= len(tokens) || tokens[i] != "{" {
			continue
		}
		i++
		for i < len(tokens) && tokens[i] != "}" {
			key := tokens[i]
			i++
			if i >= len(tokens) {
				break
			}
			val := tokens[i]
			i++
			if key == "path" {
				p := strings.ReplaceAll(val, "\\\\", "\\")
				paths = append(paths, p)
			}
		}
		if i < len(tokens) && tokens[i] == "}" {
			i++
		}
	}
	return paths
}

// vdfTokenize splits raw VDF bytes into quoted-string tokens.
func vdfTokenize(data []byte) []string {
	var tokens []string
	i := 0
	for i < len(data) {
		// Skip whitespace and comments
		for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n') {
			i++
		}
		if i >= len(data) {
			break
		}
		if data[i] == '/' && i+1 < len(data) && data[i+1] == '/' {
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		// Brace tokens
		if data[i] == '{' || data[i] == '}' {
			tokens = append(tokens, string(data[i]))
			i++
			continue
		}
		// Quoted string
		if data[i] == '"' {
			i++
			start := i
			for i < len(data) && data[i] != '"' {
				if data[i] == '\\' && i+1 < len(data) {
					i += 2
					continue
				}
				i++
			}
			if i > start {
				tokens = append(tokens, unescapeVDF(data[start:i]))
			} else {
				tokens = append(tokens, "")
			}
			if i < len(data) {
				i++ // skip closing quote
			}
			continue
		}
		// Unquoted token (rare in VDF)
		start := i
		for i < len(data) && data[i] != ' ' && data[i] != '\t' && data[i] != '\n' && data[i] != '\r' && data[i] != '{' && data[i] != '}' {
			i++
		}
		if i > start {
			tokens = append(tokens, string(data[start:i]))
		}
	}
	return tokens
}

func unescapeVDF(s []byte) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			case 'r':
				out = append(out, '\r')
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			default:
				out = append(out, s[i])
			}
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}
