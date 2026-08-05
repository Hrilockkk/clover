//go:build windows
// +build windows

package winapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"scanner/internal/models"
)

type wmiProcessor struct {
	Name        string `wmi:"Name"`
	ProcessorID string `wmi:"ProcessorId"`
}

type wmiBaseBoard struct {
	Manufacturer string `wmi:"Manufacturer"`
	Product      string `wmi:"Product"`
	SerialNumber string `wmi:"SerialNumber"`
}

type wmiVideoController struct {
	Name        string `wmi:"Name"`
	PNPDeviceID string `wmi:"PNPDeviceID"`
}

type wmiPhysicalMemory struct {
	Capacity     uint64 `wmi:"Capacity"`
	Speed        uint32 `wmi:"Speed"`
	Manufacturer string `wmi:"Manufacturer"`
}

type wmiDiskDrive struct {
	Model        string `wmi:"Model"`
	SerialNumber string `wmi:"SerialNumber"`
	Size         uint64 `wmi:"Size"`
	DeviceID     string `wmi:"DeviceID"`
}

type wmiPhysicalMedia struct {
	Tag          string `wmi:"Tag"`
	SerialNumber string `wmi:"SerialNumber"`
}

type wmiComputerSystem struct {
	Manufacturer string `wmi:"Manufacturer"`
	Model        string `wmi:"Model"`
}

type wmiSystemEnclosure struct {
	SerialNumber string `wmi:"SerialNumber"`
}

type wmiBIOS struct {
	SerialNumber      string `wmi:"SerialNumber"`
	SMBIOSBIOSVersion string `wmi:"SMBIOSBIOSVersion"`
}

// CollectHardware gathers all hardware identifiers via WMI, registry, and
// environment. Returns a fully populated HardwareInfo including a computed HWID.
func CollectHardware() (*models.HardwareInfo, error) {
	info := &models.HardwareInfo{}

	info.Hostname, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		info.Username = u.Username
	}

	info.OSVersion = getOSVersion()
	info.MachineGuid = getMachineGuid()

	var cpus []wmiProcessor
	if err := wmi.Query("SELECT Name, ProcessorId FROM Win32_Processor", &cpus); err == nil && len(cpus) > 0 {
		info.CPUName = strings.TrimSpace(cpus[0].Name)
		info.CPUID = strings.TrimSpace(cpus[0].ProcessorID)
	}

	var boards []wmiBaseBoard
	if err := wmi.Query("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard", &boards); err == nil && len(boards) > 0 {
		info.BoardVendor = strings.TrimSpace(boards[0].Manufacturer)
		info.BoardProduct = strings.TrimSpace(boards[0].Product)
		info.BoardSerial = strings.TrimSpace(boards[0].SerialNumber)
	}

	var gpus []wmiVideoController
	if err := wmi.Query("SELECT Name, PNPDeviceID FROM Win32_VideoController", &gpus); err == nil && len(gpus) > 0 {
		info.GPUName = strings.TrimSpace(gpus[0].Name)
		info.GPUUID = strings.TrimSpace(gpus[0].PNPDeviceID)
	}

	var ram []wmiPhysicalMemory
	if err := wmi.Query("SELECT Capacity, Speed, Manufacturer FROM Win32_PhysicalMemory", &ram); err == nil {
		for _, r := range ram {
			info.RAM = append(info.RAM, models.RAMModule{
				CapacityMB:   r.Capacity / (1024 * 1024),
				Speed:        r.Speed,
				Manufacturer: strings.TrimSpace(r.Manufacturer),
			})
		}
	}

	var media []wmiPhysicalMedia
	mediaMap := make(map[string]string)
	if err := wmi.Query("SELECT Tag, SerialNumber FROM Win32_PhysicalMedia", &media); err == nil {
		for _, m := range media {
			mediaMap[strings.ToLower(strings.TrimSpace(m.Tag))] = strings.TrimSpace(m.SerialNumber)
		}
	}

	var drives []wmiDiskDrive
	if err := wmi.Query("SELECT Model, SerialNumber, Size, DeviceID FROM Win32_DiskDrive", &drives); err == nil {
		for _, d := range drives {
			serial := strings.TrimSpace(d.SerialNumber)
			if serial == "" {
				if s, ok := mediaMap[strings.ToLower(strings.TrimSpace(d.DeviceID))]; ok {
					serial = s
				}
			}
			info.Disks = append(info.Disks, models.DiskHardwareInfo{
				Model:        strings.TrimSpace(d.Model),
				SerialNumber: serial,
				SizeGB:       float64(d.Size) / (1024 * 1024 * 1024),
			})
		}
	}

	var systems []wmiComputerSystem
	if err := wmi.Query("SELECT Manufacturer, Model FROM Win32_ComputerSystem", &systems); err == nil && len(systems) > 0 {
		// We don't store system vendor/model separately, but we can if needed.
		_ = systems[0]
	}

	var enclosures []wmiSystemEnclosure
	var bios []wmiBIOS
	sysSerial := ""
	if err := wmi.Query("SELECT SerialNumber FROM Win32_SystemEnclosure", &enclosures); err == nil && len(enclosures) > 0 {
		sysSerial = strings.TrimSpace(enclosures[0].SerialNumber)
	}
	if err := wmi.Query("SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS", &bios); err == nil && len(bios) > 0 {
		if sysSerial == "" {
			sysSerial = strings.TrimSpace(bios[0].SerialNumber)
		}
		info.BIOSVersion = strings.TrimSpace(bios[0].SMBIOSBIOSVersion)
	}
	info.SystemSerial = sysSerial

	info.USB = CollectUSBHistory()

	info.HWID = computeHWID(info)
	return info, nil
}

func getOSVersion() string {
	ver := windows.RtlGetVersion()
	if ver == nil {
		return "unknown"
	}
	return fmt.Sprintf("Windows %d.%d.%d", ver.MajorVersion, ver.MinorVersion, ver.BuildNumber)
}

func getMachineGuid() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	guid, _, _ := k.GetStringValue("MachineGuid")
	return guid
}

// computeHWID builds a deterministic fingerprint hash from the most stable
// hardware identifiers: CPU ID, board serial, first disk serial, MachineGuid.
func computeHWID(info *models.HardwareInfo) string {
	var parts []string
	if info.CPUID != "" {
		parts = append(parts, info.CPUID)
	}
	if info.BoardSerial != "" && !strings.EqualFold(info.BoardSerial, "none") {
		parts = append(parts, info.BoardSerial)
	}
	if len(info.Disks) > 0 && info.Disks[0].SerialNumber != "" {
		parts = append(parts, info.Disks[0].SerialNumber)
	}
	if info.MachineGuid != "" {
		parts = append(parts, info.MachineGuid)
	}
	if len(parts) == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:16])
}
