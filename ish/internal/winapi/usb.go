package winapi

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"scanner/internal/models"
)

// CollectUSBHistory enumerates USB device history from the Windows registry.
// It reads HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR (removable storage)
// and HKLM\SYSTEM\CurrentControlSet\Enum\USB (all USB devices).
func CollectUSBHistory() []models.USBDevice {
	var out []models.USBDevice
	seen := make(map[string]bool)

	// USBSTOR first — these are the interesting ones (flash drives, external disks).
	out = append(out, enumerateUSBSTOR(seen)...)
	// USB second — all other USB devices.
	out = append(out, enumerateUSB(seen)...)

	return out
}

func enumerateUSBSTOR(seen map[string]bool) []models.USBDevice {
	const root = `SYSTEM\CurrentControlSet\Enum\USBSTOR`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[USB] open USBSTOR failed: %v\n", err)
		return nil
	}
	defer k.Close()

	deviceTypes, err := k.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[USB] enumerate USBSTOR failed: %v\n", err)
		return nil
	}

	var devices []models.USBDevice
	for _, dtype := range deviceTypes {
		dk, err := registry.OpenKey(k, dtype, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		serials, err := dk.ReadSubKeyNames(-1)
		dk.Close()
		if err != nil {
			continue
		}
		for _, serial := range serials {
			idKey := dtype + "\\" + serial
			sk, err := registry.OpenKey(k, idKey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			dev := readUSBDeviceFromKey(sk, serial, true)
			sk.Close()
			dev.HardwareID = dtype
			if key := uniqueUSBKey(dev); !seen[key] {
				seen[key] = true
				devices = append(devices, dev)
			}
		}
	}
	return devices
}

func enumerateUSB(seen map[string]bool) []models.USBDevice {
	const root = `SYSTEM\CurrentControlSet\Enum\USB`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, root, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[USB] open USB failed: %v\n", err)
		return nil
	}
	defer k.Close()

	vids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[USB] enumerate USB failed: %v\n", err)
		return nil
	}

	var devices []models.USBDevice
	for _, vidpid := range vids {
		vk, err := registry.OpenKey(k, vidpid, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		serials, err := vk.ReadSubKeyNames(-1)
		vk.Close()
		if err != nil {
			continue
		}
		for _, serial := range serials {
			idKey := vidpid + "\\" + serial
			sk, err := registry.OpenKey(k, idKey, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			dev := readUSBDeviceFromKey(sk, serial, false)
			sk.Close()
			dev.HardwareID = vidpid
			if key := uniqueUSBKey(dev); !seen[key] {
				seen[key] = true
				devices = append(devices, dev)
			}
		}
	}
	return devices
}

func readUSBDeviceFromKey(k registry.Key, serial string, removable bool) models.USBDevice {
	dev := models.USBDevice{
		SerialNumber: serial,
		IsRemovable:  removable,
	}
	if v, _, _ := k.GetStringValue("FriendlyName"); v != "" {
		dev.FriendlyName = cleanUSBName(v)
	}
	if v, _, _ := k.GetStringValue("DeviceDesc"); v != "" && dev.FriendlyName == "" {
		dev.FriendlyName = cleanUSBName(v)
	}
	if v, _, _ := k.GetStringValue("Mfg"); v != "" {
		dev.Manufacturer = v
	}
	if v, _, _ := k.GetStringValue("SerialNumber"); v != "" && dev.SerialNumber == "" {
		dev.SerialNumber = v
	}
	if v, _, _ := k.GetStringValue("Class"); v != "" {
		dev.Class = v
	}
	if v, _, _ := k.GetStringValue("Driver"); v != "" {
		dev.Driver = v
	}

	// Try to parse VID/PID from the key path if the HardwareID is not set yet.
	if dev.VID == "" || dev.PID == "" {
		dev.VID, dev.PID = parseVidPid(dev.HardwareID)
	}
	if dev.VID == "" || dev.PID == "" {
		hwid, _, _ := k.GetStringValue("HardwareID")
		if hwid == "" {
			// HardwareID is sometimes a multi-string; try the first one.
			hwids, _, _ := k.GetStringsValue("HardwareID")
			if len(hwids) > 0 {
				hwid = hwids[0]
			}
		}
		dev.VID, dev.PID = parseVidPid(hwid)
	}

	// Timestamps are usually stored as REG_QWORD FILETIME values. Try to read
	// them as integers first; fall back to the key's last write time.
	const minValidYear = 2000
	if t := readUSBFiletime(k, "InstallDate"); !t.IsZero() && t.Year() >= minValidYear {
		dev.FirstSeen = t
	}
	if dev.FirstSeen.IsZero() {
		if t := readUSBFiletime(k, "FirstInstallDate"); !t.IsZero() && t.Year() >= minValidYear {
			dev.FirstSeen = t
		}
	}
	if t := readUSBFiletime(k, "LastArrivalDate"); !t.IsZero() && t.Year() >= minValidYear {
		dev.LastSeen = t
	}
	if dev.LastSeen.IsZero() {
		if t := readUSBFiletime(k, "LastRemovalDate"); !t.IsZero() && t.Year() >= minValidYear {
			dev.LastSeen = t
		}
	}
	if dev.FirstSeen.IsZero() || dev.LastSeen.IsZero() {
		if info, err := k.Stat(); err == nil && !info.ModTime().IsZero() && info.ModTime().Year() >= minValidYear {
			if dev.FirstSeen.IsZero() {
				dev.FirstSeen = info.ModTime()
			}
			if dev.LastSeen.IsZero() {
				dev.LastSeen = info.ModTime()
			}
		}
	}

	return dev
}

// readUSBFiletime reads a 64-bit FILETIME from the registry value (REG_QWORD).
// It returns zero time if the value is missing or not a valid FILETIME.
func readUSBFiletime(k registry.Key, name string) time.Time {
	v, _, err := k.GetIntegerValue(name)
	if err != nil || v == 0 || v == ^uint64(0) {
		return time.Time{}
	}
	return filetimeToTime(int64(v))
}

func filetimeToTime(ft int64) time.Time {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	seconds := ft/ticksPerSecond - epochDiff
	nsec := (ft % ticksPerSecond) * 100
	if seconds < 0 {
		return time.Time{}
	}
	return time.Unix(seconds, nsec)
}

// cleanUSBName removes INF template prefixes like "@usbhub3.inf,%usbhub3.roothubdevicedesc%;"
// and returns the human-readable display name.
func cleanUSBName(s string) string {
	// Strip everything up to and including the last semicolon.
	if idx := strings.LastIndex(s, ";"); idx >= 0 && idx+1 < len(s) {
		s = s[idx+1:]
	}
	return strings.TrimSpace(s)
}

func parseVidPid(s string) (vid, pid string) {
	u := strings.ToUpper(s)
	vidIdx := strings.Index(u, "VID_")
	if vidIdx < 0 || vidIdx+8 > len(s) {
		return "", ""
	}
	vidPart := u[vidIdx+4 : vidIdx+8]
	if !isHexString(vidPart) {
		return "", ""
	}
	vid = vidPart

	pidIdx := strings.Index(u, "PID_")
	if pidIdx < 0 || pidIdx+8 > len(s) {
		return vid, ""
	}
	pidPart := u[pidIdx+4 : pidIdx+8]
	if !isHexString(pidPart) {
		return vid, ""
	}
	pid = pidPart
	return vid, pid
}

func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func uniqueUSBKey(d models.USBDevice) string {
	return strings.ToUpper(d.VID + "_" + d.PID + "_" + d.SerialNumber)
}
