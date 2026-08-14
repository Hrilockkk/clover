//go:build windows
// +build windows

package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"scanner/internal/models"
	"scanner/internal/utils"
	"scanner/internal/winapi"
)

const (
	fsctlQueryUSNJournal = 0x000900f4
	fsctlEnumUSNData     = 0x000900b3
	fsctlReadUSNJournal  = 0x000900bb
)

const usnReasonFileDelete = 0x00000200

// ScanOptions tunes raw-MFT and deleted-file scanning limits.
type ScanOptions struct {
	MaxRecords            int64
	BatchSize             int
	MaxDeletedContentSize int64
	MaxDeletedSearchSize  int64
}

func (o *ScanOptions) applyDefaults() {
	if o == nil {
		return
	}
	if o.MaxRecords <= 0 {
		o.MaxRecords = 2_000_000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 4 * 1024 * 1024
	}
	if o.MaxDeletedContentSize <= 0 {
		o.MaxDeletedContentSize = 64 * 1024 * 1024
	}
	if o.MaxDeletedSearchSize <= 0 {
		o.MaxDeletedSearchSize = 100 * 1024 * 1024
	}
}

type usnJournalDataV0 struct {
	UsnJournalID        uint64
	FirstUsn            int64
	NextUsn             int64
	LowestValidUsn      int64
	MaxUsn              int64
	MaximumSize         uint64
	AllocationDelta     uint64
	MinSupportedMajor   uint16
	MaxSupportedMajor   uint16
	Flags               uint32
	RangeTrackChunkSize uint64
	RangeTrackFileSize  int64
}

type readUsnJournalDataV0 struct {
	StartUsn          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

type mftEnumDataV0 struct {
	StartFileReferenceNumber uint64
	LowUsn                   int64
	HighUsn                  int64
}

type usnRecordV2 struct {
	RecordLength           uint32
	MajorVersion           uint16
	MinorVersion           uint16
	FileReferenceNumber    uint64
	ParentFileReferenceNum uint64
	Usn                    int64
	TimeStamp              int64
	Reason                 uint32
	SourceInfo             uint32
	SecurityId             uint32
	FileAttributes         uint32
	FileNameLength         uint16
	FileNameOffset         uint16
}

// ReadNTFSBootSector parses the NTFS boot sector from a raw volume.
func ReadNTFSBootSector(drive string) (*models.NTFSBootSector, error) {
	path := `\\.\` + strings.TrimSuffix(drive, "\\")
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	var boot [512]byte
	var read uint32
	if err := windows.ReadFile(h, boot[:], &read, nil); err != nil {
		return nil, err
	}
	if string(boot[3:11]) != "NTFS    " {
		return nil, fmt.Errorf("not NTFS")
	}

	return &models.NTFSBootSector{
		BytesPerSector:       binary.LittleEndian.Uint16(boot[0x0B:]),
		SectorsPerCluster:    boot[0x0D],
		MFTStartLCN:          int64(binary.LittleEndian.Uint64(boot[0x28:])),
		ClustersPerMFTRecord: int8(boot[0x38]),
	}, nil
}

// MFTRecordSizeFromBoot computes the MFT record size.
func MFTRecordSizeFromBoot(b *models.NTFSBootSector) int {
	if b.ClustersPerMFTRecord > 0 {
		return int(b.ClustersPerMFTRecord) * int(b.BytesPerSector) * int(b.SectorsPerCluster)
	}
	return 1 << (-int(b.ClustersPerMFTRecord))
}

func applyMFTFixup(data []byte, bytesPerSector uint16) bool {
	if len(data) < 8 {
		return false
	}
	usOffset := binary.LittleEndian.Uint16(data[0x04:])
	usSize := binary.LittleEndian.Uint16(data[0x06:])
	// usSize == 1 means USN only (no sector tails) — nothing to fix up.
	if usSize < 1 || int(usOffset)+int(usSize)*2 > len(data) {
		return false
	}
	usn := data[usOffset : usOffset+2]
	for i := uint16(1); i < usSize; i++ {
		pos := int(i)*int(bytesPerSector) - 2
		if pos < 0 || pos+2 > len(data) {
			return false
		}
		// The trailing bytes of every sector must equal the update sequence
		// number; a mismatch means a stale/corrupt record — refuse to "fix"
		// it, otherwise we would silently corrupt the buffer.
		if data[pos] != usn[0] || data[pos+1] != usn[1] {
			return false
		}
		fixOffset := int(usOffset) + int(i)*2
		data[pos] = data[fixOffset]
		data[pos+1] = data[fixOffset+1]
	}
	return true
}

// ParseMFTRecord decodes a single raw MFT FILE record.
func ParseMFTRecord(data []byte, b *models.NTFSBootSector) (*models.MFTParsedRecord, error) {
	if len(data) < 0x30 || string(data[0:4]) != "FILE" {
		return nil, fmt.Errorf("invalid record")
	}

	if !applyMFTFixup(data, b.BytesPerSector) {
		return nil, fmt.Errorf("fixup failed")
	}

	flags := binary.LittleEndian.Uint16(data[0x16:])
	firstAttr := binary.LittleEndian.Uint16(data[0x14:])
	recNum := binary.LittleEndian.Uint32(data[0x2C:])

	res := &models.MFTParsedRecord{
		IsInUse:      flags&0x01 != 0,
		IsDir:        flags&0x02 != 0,
		MFTRecordNum: uint64(recNum),
	}

	bestNs := -1
	offset := int(firstAttr)
	for offset < len(data)-8 {
		attrType := binary.LittleEndian.Uint32(data[offset:])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := binary.LittleEndian.Uint32(data[offset+4:])
		if attrLen == 0 || offset+int(attrLen) > len(data) {
			break
		}

		switch attrType {
		case 0x10: // $STANDARD_INFORMATION
			parseStandardInfo(data[offset:offset+int(attrLen)], res)
		case 0x30: // $FILE_NAME
			parseFileNameAttr(data[offset:offset+int(attrLen)], res, &bestNs)
		case 0x80: // $DATA
			parseDataAttr(data[offset:offset+int(attrLen)], res)
		}

		offset += int(attrLen)
	}

	return res, nil
}

// parseMFTRecordFast is a lightweight MFT record parser that extracts only
// the fields needed for indexing (name, parent FRN, size, flags). It skips
// $STANDARD_INFORMATION timestamps and $DATA content, making it significantly
// faster for building the node map over millions of records. Deleted .exe
// candidates that need content should be re-parsed with the full ParseMFTRecord.
func parseMFTRecordFast(data []byte, b *models.NTFSBootSector) (*models.MFTParsedRecord, error) {
	if len(data) < 0x30 || string(data[0:4]) != "FILE" {
		return nil, fmt.Errorf("invalid record")
	}

	if !applyMFTFixup(data, b.BytesPerSector) {
		return nil, fmt.Errorf("fixup failed")
	}

	flags := binary.LittleEndian.Uint16(data[0x16:])
	firstAttr := binary.LittleEndian.Uint16(data[0x14:])
	recNum := binary.LittleEndian.Uint32(data[0x2C:])

	res := &models.MFTParsedRecord{
		IsInUse:      flags&0x01 != 0,
		IsDir:        flags&0x02 != 0,
		MFTRecordNum: uint64(recNum),
	}

	bestNs := -1
	offset := int(firstAttr)
	for offset < len(data)-8 {
		attrType := binary.LittleEndian.Uint32(data[offset:])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := binary.LittleEndian.Uint32(data[offset+4:])
		if attrLen == 0 || offset+int(attrLen) > len(data) {
			break
		}

		if attrType == 0x30 { // $FILE_NAME
			parseFileNameAttr(data[offset:offset+int(attrLen)], res, &bestNs)
			if bestNs >= fileNameNamespaceScore(1) {
				// Win32 (or Win32&DOS) name captured — good enough for
				// indexing, stop scanning attributes.
				break
			}
		}
		offset += int(attrLen)
	}

	return res, nil
}

func parseStandardInfo(data []byte, res *models.MFTParsedRecord) {
	if len(data) < 0x18 || data[0x08] != 0 {
		return
	}
	valOff := binary.LittleEndian.Uint16(data[0x14:])
	if int(valOff)+0x30 > len(data) {
		return
	}
	v := data[valOff:]
	res.CreationTime = winapi.FiletimeToTime(windows.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(v[0x00:]),
		HighDateTime: binary.LittleEndian.Uint32(v[0x04:]),
	})
	res.ModifiedTime = winapi.FiletimeToTime(windows.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(v[0x08:]),
		HighDateTime: binary.LittleEndian.Uint32(v[0x0C:]),
	})
}

// fileNameNamespaceScore ranks $FILE_NAME namespaces: a record can carry
// several names (POSIX/Win32/DOS 8.3); we always prefer the Win32 one,
// otherwise paths would surface as short DOS aliases (e.g. "CHEAT~1.EXE").
func fileNameNamespaceScore(ns byte) int {
	switch ns {
	case 3: // Win32 & DOS
		return 4
	case 1: // Win32
		return 3
	case 0: // POSIX
		return 2
	default: // 2 = DOS
		return 1
	}
}

func parseFileNameAttr(data []byte, res *models.MFTParsedRecord, bestNs *int) {
	if len(data) < 0x42 || data[0x08] != 0 {
		return
	}
	valOff := binary.LittleEndian.Uint16(data[0x14:])
	if int(valOff)+0x42 > len(data) {
		return
	}
	v := data[valOff:]
	score := fileNameNamespaceScore(v[0x41])
	if bestNs != nil && score <= *bestNs {
		return // a better (Win32) name is already stored
	}

	nameLen := int(v[0x40])
	if nameLen == 0 || int(valOff)+0x42+nameLen*2 > len(data) {
		return
	}

	res.ParentFRN = binary.LittleEndian.Uint64(v[0x00:])
	res.Size = int64(binary.LittleEndian.Uint64(v[0x30:]))
	res.Name = utils.DecodeUTF16(v[0x42 : 0x42+nameLen*2])
	if bestNs != nil {
		*bestNs = score
	}
}

func parseDataAttr(data []byte, res *models.MFTParsedRecord) {
	if len(data) < 0x18 {
		return
	}
	nameLen := int(data[0x09])
	nameOff := binary.LittleEndian.Uint16(data[0x0A:])
	var attrName string
	if nameLen > 0 && int(nameOff)+nameLen*2 <= len(data) {
		attrName = utils.DecodeUTF16(data[nameOff:uint16(int(nameOff)+nameLen*2)])
	}

	if data[0x08] == 0 {
		// Resident: only the unnamed $DATA stream is kept; named streams (ADS)
		// are skipped — nothing consumes them downstream.
		valOff := int(binary.LittleEndian.Uint16(data[0x14:]))
		valLen := int(binary.LittleEndian.Uint32(data[0x10:]))
		if attrName == "" && valOff+valLen <= len(data) {
			res.ResidentData = make([]byte, valLen)
			copy(res.ResidentData, data[valOff:valOff+valLen])
		}
	} else {
		// Non-resident
		if attrName == "" {
			res.HasNonResident = true
			runOff := binary.LittleEndian.Uint16(data[0x20:])
			if int(runOff) < len(data) {
				res.Runlist = data[runOff:]
			}
			if res.Size == 0 && len(data) >= 0x40 {
				res.Size = int64(binary.LittleEndian.Uint64(data[0x30:]))
			}
		}
		// Non-resident named ADS: skip content reading (would need runlist parsing per stream)
	}
}

// ReadRunlistData reads clusters referenced by an NTFS runlist.
func ReadRunlistData(h windows.Handle, runlist []byte, clusterSize int64) []byte {
	if len(runlist) == 0 {
		return nil
	}
	var result []byte
	prevCluster := int64(0)
	offset := 0
	for offset < len(runlist) {
		header := runlist[offset]
		if header == 0 {
			break
		}
		offset++
		lenSize := int(header & 0x0F)
		offSize := int((header >> 4) & 0x0F)
		if offset+lenSize+offSize > len(runlist) {
			break
		}

		var runLen int64
		for i := 0; i < lenSize; i++ {
			runLen |= int64(runlist[offset+i]) << (i * 8)
		}
		offset += lenSize

		var runOffset int64
		for i := 0; i < offSize; i++ {
			runOffset |= int64(runlist[offset+i]) << (i * 8)
		}
		if offSize > 0 && runlist[offset+offSize-1]&0x80 != 0 {
			runOffset |= int64(-1) << (offSize * 8)
		}
		offset += offSize

		if offSize == 0 {
			result = append(result, make([]byte, runLen*clusterSize)...)
		} else {
			prevCluster += runOffset
			data := readClusters(h, prevCluster, runLen, clusterSize)
			result = append(result, data...)
		}
	}
	return result
}

func readClusters(h windows.Handle, startCluster, count, clusterSize int64) []byte {
	offset := startCluster * clusterSize
	_, err := windows.Seek(h, offset, 0)
	if err != nil {
		return nil
	}
	size := count * clusterSize
	if size > 50*1024*1024 {
		size = 50 * 1024 * 1024
	}
	buf := make([]byte, size)
	var read uint32
	err = windows.ReadFile(h, buf, &read, nil)
	if err != nil {
		return nil
	}
	return buf[:read]
}

// ResolveDeletedPath rebuilds a full path from an FRN using a node map.
func ResolveDeletedPath(frn uint64, nodes map[uint64]models.MFTNode, drive string) string {
	var parts []string
	seen := make(map[uint64]bool)
	cur := frn
	for {
		if seen[cur] {
			break
		}
		seen[cur] = true
		node, ok := nodes[cur]
		if !ok || cur == 0 || cur == 5 {
			break
		}
		if node.Name != "" {
			parts = append(parts, node.Name)
		}
		cur = node.Parent
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return drive + "\\" + strings.Join(parts, "\\")
}

// ScanDeletedViaRawMFT searches the raw MFT for deleted .exe files matching rules.
func ScanDeletedViaRawMFT(drive string, resolver *PathResolver, rules []models.SearchRule, opts *ScanOptions) (foundFiles []models.FileInfo, err error) {
	opts.applyDefaults()
	boot, err := ReadNTFSBootSector(drive)
	if err != nil {
		fmt.Printf("[MFT] %s boot read failed: %v\n", drive, err)
		return nil, err
	}

	recordSize := MFTRecordSizeFromBoot(boot)
	clusterSize := int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)
	mftStart := boot.MFTStartLCN * clusterSize
	fmt.Printf("[MFT] %s recordSize=%d clusterSize=%d scanning raw MFT for deleted files...\n", drive, recordSize, clusterSize)

	path := `\\.\` + strings.TrimSuffix(drive, "\\")
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	maxRecords := opts.MaxRecords
	batchBytes := opts.BatchSize
	found := 0
	recordNum := int64(0)
	lastReport := time.Now()
	reportInterval := 3 * time.Second

	for recordNum < maxRecords {
		offset := mftStart + recordNum*int64(recordSize)
		_, err := windows.Seek(h, offset, 0)
		if err != nil {
			break
		}

		bufSize := batchBytes
		remaining := (maxRecords - recordNum) * int64(recordSize)
		if remaining < int64(bufSize) {
			bufSize = int(remaining)
		}
		if bufSize <= 0 {
			break
		}

		buf := make([]byte, bufSize)
		var read uint32
		err = windows.ReadFile(h, buf, &read, nil)
		if err != nil || read == 0 {
			break
		}

		recordsInBuf := int(read) / recordSize
		if recordsInBuf == 0 {
			break
		}

		recBuf := make([]byte, recordSize)
		for i := 0; i < recordsInBuf && recordNum < maxRecords; i++ {
			start := i * recordSize
			copy(recBuf, buf[start:start+recordSize])

			rec, err := ParseMFTRecord(recBuf, boot)
			recordNum++
			if err != nil || rec.IsInUse || rec.IsDir || rec.Name == "" {
				continue
			}

			if !strings.HasSuffix(strings.ToLower(rec.Name), ".exe") {
				continue
			}

			fits := false
			for _, r := range rules {
				if rec.Size >= r.Min && rec.Size <= r.Max {
					fits = true
					break
				}
			}
			if !fits {
				continue
			}

			filePath := resolver.Resolve(rec.ParentFRN)
			if filePath != drive+"\\" {
				filePath = filePath + "\\" + rec.Name
			} else {
				filePath = drive + "\\" + rec.Name
			}

			contentToSearch := rec.ResidentData
			if contentToSearch == nil && rec.HasNonResident && len(rec.Runlist) > 0 && rec.Size <= opts.MaxDeletedSearchSize {
				contentToSearch = ReadRunlistData(h, rec.Runlist, clusterSize)
			}
			if int64(len(contentToSearch)) > opts.MaxDeletedContentSize {
				contentToSearch = contentToSearch[:opts.MaxDeletedContentSize]
			}

			matched := ""
			if len(contentToSearch) > 0 {
				for _, r := range rules {
					if r.CheckPath {
						continue
					}
					if len(r.PatternBytes) > 0 && bytes.Contains(contentToSearch, r.PatternBytes) {
						matched = r.Pattern
						break
					}
					if r.UTF16 {
						if bytes.Contains(contentToSearch, r.UTF16LE) || bytes.Contains(contentToSearch, r.UTF16BE) {
							matched = r.Pattern
							break
						}
					}
				}
			}

			if matched == "" {
				matched = "DELETED_RAW_MFT"
			}

			// A zero ModifiedTime stays zero: substituting time.Now() would
			// present a made-up deletion time in the report.
			foundFiles = append(foundFiles, models.FileInfo{
				Path:       filePath,
				Name:       rec.Name,
				Size:       rec.Size,
				Attributes: "DELETED",
				Matched:    matched,
				Modified:   rec.ModifiedTime,
				Deleted:    rec.ModifiedTime,
			})
			found++
		}

		if time.Since(lastReport) > reportInterval {
			lastReport = time.Now()
			fmt.Printf("\r[MFT] %s scanning raw MFT record %d/%d, found %d...", drive, recordNum, maxRecords, found)
		}
	}

	fmt.Printf("\n[MFT] %s found %d deleted .exe files via raw MFT\n", drive, found)
	return foundFiles, nil
}

// RawMFTResult holds everything extracted from a single sequential MFT pass.
type RawMFTResult struct {
	Resolver     *PathResolver
	ExePaths     []string
	DeletedFiles []models.FileInfo
	TargetDirs   []models.DirInfo
	TargetFiles  []models.NamedFileInfo
}

// ScanRawMFT reads the raw $MFT in a single sequential pass — the voidtools
// Everything approach — and extracts everything in one I/O sweep:
//   - complete FRN→node map (for path resolution)
//   - live .exe file paths
//   - deleted .exe files matching size rules (with content for matching)
//   - target directories and target files (by name)
//
// This replaces the separate USN-enum + raw-MFT-scan with one sequential read.
// Non-resident $DATA for deleted candidates is read after the sequential sweep
// to avoid breaking sequential I/O.
func ScanRawMFT(drive string, rules []models.SearchRule, targetDirNames, targetFileNames []string, opts *ScanOptions) (*RawMFTResult, error) {
	opts.applyDefaults()
	boot, err := ReadNTFSBootSector(drive)
	if err != nil {
		return nil, fmt.Errorf("boot sector: %w", err)
	}
	recordSize := MFTRecordSizeFromBoot(boot)
	clusterSize := int64(boot.BytesPerSector) * int64(boot.SectorsPerCluster)
	mftStart := boot.MFTStartLCN * clusterSize

	volumePath := `\\.\` + strings.TrimSuffix(drive, "\\")
	ptr, err := windows.UTF16PtrFromString(volumePath)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(ptr, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	dirSet := make(map[string]struct{}, len(targetDirNames))
	for _, n := range targetDirNames {
		dirSet[strings.ToLower(n)] = struct{}{}
	}
	fileSet := make(map[string]struct{}, len(targetFileNames))
	for _, n := range targetFileNames {
		fileSet[strings.ToLower(n)] = struct{}{}
	}

	nodes := make(map[uint64]models.MFTNode, 524288)
	liveExeFRNs := make([]uint64, 0, 65536)

	type deletedCand struct{ rec *models.MFTParsedRecord }
	var deletedCands []deletedCand

	type targetCand struct {
		frn   uint64
		isDir bool
		name  string
	}
	var targetCands []targetCand

	batchSize := opts.BatchSize
	buf := make([]byte, batchSize)
	recBuf := make([]byte, recordSize)
	recordNum := int64(0)
	consecutiveBad := 0
	lastReport := time.Now()

sequential:
	for recordNum < opts.MaxRecords {
		offset := mftStart + recordNum*int64(recordSize)
		_, err := windows.Seek(h, offset, 0)
		if err != nil {
			break
		}

		var read uint32
		err = windows.ReadFile(h, buf, &read, nil)
		if err != nil || read == 0 {
			break
		}

		recordsInBuf := int(read) / recordSize
		if recordsInBuf == 0 {
			break
		}

		for i := 0; i < recordsInBuf; i++ {
			start := i * recordSize
			if start+4 > len(buf) || string(buf[start:start+4]) != "FILE" {
				recordNum++
				consecutiveBad++
				if consecutiveBad >= 256 {
					break sequential
				}
				continue
			}
			consecutiveBad = 0
			copy(recBuf, buf[start:start+recordSize])

			rec, perr := parseMFTRecordFast(recBuf, boot)
			recordNum++
			if perr != nil || rec.Name == "" {
				continue
			}

			nodes[rec.MFTRecordNum] = models.MFTNode{
				Name:   rec.Name,
				Parent: rec.ParentFRN,
				IsDir:  rec.IsDir,
			}

			lowerName := strings.ToLower(rec.Name)

			if rec.IsDir {
				if _, ok := dirSet[lowerName]; ok {
					targetCands = append(targetCands, targetCand{frn: rec.MFTRecordNum, isDir: true, name: rec.Name})
				}
			} else {
				if _, ok := fileSet[lowerName]; ok {
					targetCands = append(targetCands, targetCand{frn: rec.MFTRecordNum, isDir: false, name: rec.Name})
				}

				if !strings.HasSuffix(lowerName, ".exe") {
					continue
				}

				if rec.IsInUse {
					liveExeFRNs = append(liveExeFRNs, rec.MFTRecordNum)
					continue
				}

				// Deleted .exe — check size rules
				fits := false
				for _, r := range rules {
					if rec.Size >= r.Min && rec.Size <= r.Max {
						fits = true
						break
					}
				}
				if !fits {
					continue
				}

				// Full parse to get $DATA content + timestamps
				fullRec, ferr := ParseMFTRecord(recBuf, boot)
				if ferr != nil {
					continue
				}
				fullRecCopy := &models.MFTParsedRecord{
					IsInUse:        fullRec.IsInUse,
					IsDir:          fullRec.IsDir,
					Name:           fullRec.Name,
					Size:           fullRec.Size,
					ParentFRN:      fullRec.ParentFRN,
					CreationTime:   fullRec.CreationTime,
					ModifiedTime:   fullRec.ModifiedTime,
					ResidentData:   fullRec.ResidentData,
					HasNonResident: fullRec.HasNonResident,
					Runlist:        append([]byte(nil), fullRec.Runlist...),
					MFTRecordNum:   fullRec.MFTRecordNum,
				}
				deletedCands = append(deletedCands, deletedCand{rec: fullRecCopy})
			}
		}

		if time.Since(lastReport) > 3*time.Second {
			lastReport = time.Now()
			fmt.Printf("\r[MFT] %s records=%d nodes=%d exe=%d deleted=%d...",
				drive, recordNum, len(nodes), len(liveExeFRNs), len(deletedCands))
		}
	}

	fmt.Printf("\n[MFT] %s scan complete: %d records, %d nodes, %d live exe, %d deleted candidates\n",
		drive, recordNum, len(nodes), len(liveExeFRNs), len(deletedCands))

	resolver := NewPathResolver(nodes, drive)

	// Resolve live .exe paths
	exePaths := make([]string, 0, len(liveExeFRNs))
	for _, frn := range liveExeFRNs {
		exePaths = append(exePaths, resolver.Resolve(frn))
	}

	// Process deleted candidates: read non-resident $DATA + content match
	// (deferred from sequential sweep to maintain I/O sequentiality)
	deletedFiles := make([]models.FileInfo, 0, len(deletedCands))
	for _, dc := range deletedCands {
		rec := dc.rec
		parentPath := resolver.Resolve(rec.ParentFRN)
		var filePath string
		if parentPath != drive+"\\" {
			filePath = parentPath + "\\" + rec.Name
		} else {
			filePath = drive + "\\" + rec.Name
		}

		contentToSearch := rec.ResidentData
		if contentToSearch == nil && rec.HasNonResident && len(rec.Runlist) > 0 && rec.Size <= opts.MaxDeletedSearchSize {
			contentToSearch = ReadRunlistData(h, rec.Runlist, clusterSize)
		}
		if int64(len(contentToSearch)) > opts.MaxDeletedContentSize {
			contentToSearch = contentToSearch[:opts.MaxDeletedContentSize]
		}

		matched := ""
		if len(contentToSearch) > 0 {
			for _, r := range rules {
				if r.CheckPath {
					continue
				}
				if len(r.PatternBytes) > 0 && bytes.Contains(contentToSearch, r.PatternBytes) {
					matched = r.Pattern
					break
				}
				if r.UTF16 {
					if bytes.Contains(contentToSearch, r.UTF16LE) || bytes.Contains(contentToSearch, r.UTF16BE) {
						matched = r.Pattern
						break
					}
				}
			}
		}
		if matched == "" {
			matched = "DELETED_RAW_MFT"
		}

		// A zero ModifiedTime stays zero: substituting time.Now() would
		// present a made-up deletion time in the report.
		deletedFiles = append(deletedFiles, models.FileInfo{
			Path:       filePath,
			Name:       rec.Name,
			Size:       rec.Size,
			Attributes: "DELETED",
			Matched:    matched,
			Modified:   rec.ModifiedTime,
			Deleted:    rec.ModifiedTime,
		})
	}

	// Resolve target dirs/files paths and stat
	targetDirs := make([]models.DirInfo, 0, len(targetCands))
	targetFiles := make([]models.NamedFileInfo, 0, len(targetCands))
	seenDir := make(map[string]bool, len(targetCands))
	seenFile := make(map[string]bool, len(targetCands))
	for _, tc := range targetCands {
		p := resolver.Resolve(tc.frn)
		key := strings.ToLower(p)
		if tc.isDir {
			if seenDir[key] {
				continue
			}
			seenDir[key] = true
			info, serr := os.Stat(p)
			if serr != nil {
				continue
			}
			targetDirs = append(targetDirs, models.DirInfo{
				Path:       p,
				Name:       tc.name,
				Attributes: winapi.WinAttrsToString(p),
				Modified:   info.ModTime(),
			})
		} else {
			if seenFile[key] {
				continue
			}
			seenFile[key] = true
			info, serr := os.Stat(p)
			if serr != nil {
				continue
			}
			targetFiles = append(targetFiles, models.NamedFileInfo{
				Path:       p,
				Name:       tc.name,
				Size:       info.Size(),
				Attributes: winapi.WinAttrsToString(p),
				Modified:   info.ModTime(),
			})
		}
	}

	return &RawMFTResult{
		Resolver:     resolver,
		ExePaths:     exePaths,
		DeletedFiles: deletedFiles,
		TargetDirs:   targetDirs,
		TargetFiles:  targetFiles,
	}, nil
}

// cleanerININame: shellbag_analyzer_cleaner.ini in a deletion record proves
// the shellbag cleaner ran (and the player tried to hide it).
const cleanerININame = "shellbag_analyzer_cleaner.ini"

// ScanDeletedViaUSN reads the USN journal for deletion records. Deleted .exe
// entries older than windowHours are skipped (they are usually long gone from
// the MFT slack as well); 0 disables the time filter. Additionally every
// deletion of shellbag_analyzer_cleaner.ini is collected into cleanerIni
// (no extension/time filter applies to it).
func ScanDeletedViaUSN(drive string, resolver *PathResolver, rules []models.SearchRule, targetDirNames []string, windowHours int) (foundFiles []models.FileInfo, foundDirs []models.DeletedDirInfo, cleanerIni []models.DeletedIniFinding, err error) {
	h, err := winapi.OpenVolumeHandle(drive)
	if err != nil {
		return nil, nil, nil, err
	}
	defer windows.CloseHandle(h)

	journal, err := queryUSNJournal(drive)
	if err != nil {
		return nil, nil, nil, err
	}

	readData := readUsnJournalDataV0{
		StartUsn:          journal.FirstUsn,
		ReasonMask:        usnReasonFileDelete,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		UsnJournalID:      journal.UsnJournalID,
	}

	buffer := make([]byte, 1<<20)
	fileCount := 0
	pfCount := 0
	dirCount := 0
	usnRecords := 0
	lastReport := time.Now()
	reportInterval := 3 * time.Second
	windowStart := time.Time{}
	if windowHours > 0 {
		windowStart = time.Now().Add(-time.Duration(windowHours) * time.Hour)
	}

	for {
		var bytesReturned uint32
		err := winapi.DeviceIoControl(
			h,
			fsctlReadUSNJournal,
			unsafe.Pointer(&readData),
			uint32(unsafe.Sizeof(readData)),
			unsafe.Pointer(&buffer[0]),
			uint32(len(buffer)),
			&bytesReturned,
		)
		if err != nil {
			fmt.Printf("[USN] %s read journal failed: %v\n", drive, err)
			break
		}
		if bytesReturned <= 8 {
			break
		}

		nextUsn := *(*int64)(unsafe.Pointer(&buffer[0]))
		offset := uint32(8)
		for offset+uint32(unsafe.Sizeof(usnRecordV2{})) <= bytesReturned {
			rec := (*usnRecordV2)(unsafe.Pointer(&buffer[offset]))
			if rec.RecordLength == 0 || offset+rec.RecordLength > bytesReturned {
				break
			}
			usnRecords++

			if rec.FileNameLength > 0 {
				nameStart := offset + uint32(rec.FileNameOffset)
				nameChars := int(rec.FileNameLength / 2)
				namePtr := (*uint16)(unsafe.Pointer(&buffer[nameStart]))
				nameSlice := unsafe.Slice(namePtr, nameChars)
				name := windows.UTF16ToString(nameSlice)

				ts := uint64(rec.TimeStamp)
				ft := windows.Filetime{LowDateTime: uint32(ts), HighDateTime: uint32(ts >> 32)}
				deletedAt := winapi.FiletimeToTime(ft)

				isDir := rec.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
				parentPath := resolver.Resolve(rec.ParentFileReferenceNum)
				if parentPath == drive+"\\" {
					parentPath = drive
				}
				fullPath := parentPath + "\\" + name

				if isDir {
					if isTargetDirName(name, targetDirNames) || matchesTargetDirPath(fullPath, targetDirNames) {
						foundDirs = append(foundDirs, models.DeletedDirInfo{
							Path:    fullPath,
							Name:    name,
							Deleted: deletedAt,
						})
						dirCount++
					}
				} else {
					// Cleaner artefact: collected regardless of extension
					// filters and the time window.
					if strings.EqualFold(name, cleanerININame) {
						cleanerIni = append(cleanerIni, models.DeletedIniFinding{
							Name:    name,
							Path:    fullPath,
							Deleted: deletedAt,
						})
					}
					nameLower := strings.ToLower(name)
					pathLower := strings.ToLower(fullPath)
					isExe := strings.HasSuffix(nameLower, ".exe")
					isPF := strings.HasSuffix(nameLower, ".pf")
					matchesRules := matchesDeletedPath(pathLower, rules)
					matchesSuspiciousDir := matchesTargetDirPath(pathLower, targetDirNames)

					if !isExe && !isPF {
						offset += rec.RecordLength
						if usnRecords%50000 == 0 || time.Since(lastReport) > reportInterval {
							lastReport = time.Now()
							fmt.Printf("\r[USN] %s records:%d files:%d pf:%d dirs:%d ...", drive, usnRecords, fileCount, pfCount, dirCount)
						}
						continue
					}

					if isExe {
						if (!matchesRules && !matchesSuspiciousDir) || (!windowStart.IsZero() && deletedAt.Before(windowStart)) {
							offset += rec.RecordLength
							if usnRecords%50000 == 0 || time.Since(lastReport) > reportInterval {
								lastReport = time.Now()
								fmt.Printf("\r[USN] %s records:%d files:%d pf:%d dirs:%d ...", drive, usnRecords, fileCount, pfCount, dirCount)
							}
							continue
						}
						matchedTag := "USN_DELETED"
						if matchesSuspiciousDir && !matchesRules {
							matchedTag = "USN_DELETED (suspicious dir)"
						}
						foundFiles = append(foundFiles, models.FileInfo{
							Path:       fullPath,
							Name:       name,
							Size:       0,
							Attributes: "DELETED",
							Matched:    matchedTag,
							Modified:   deletedAt,
							Deleted:    deletedAt,
						})
						fileCount++
					}

					if isPF {
						foundFiles = append(foundFiles, models.FileInfo{
							Path:       fullPath,
							Name:       name,
							Size:       0,
							Attributes: "DELETED",
							Matched:    "PF_DELETED",
							Modified:   deletedAt,
							Deleted:    deletedAt,
						})
						pfCount++
					}
				}
			}

			offset += rec.RecordLength
			if usnRecords%50000 == 0 || time.Since(lastReport) > reportInterval {
				lastReport = time.Now()
				fmt.Printf("\r[USN] %s records:%d files:%d pf:%d dirs:%d ...", drive, usnRecords, fileCount, pfCount, dirCount)
			}
		}

		if nextUsn <= readData.StartUsn || nextUsn >= journal.NextUsn {
			break
		}
		readData.StartUsn = nextUsn
	}

	fmt.Printf("\n[USN] %s found %d deleted .exe files, %d deleted .pf files, %d deleted dirs via USN journal (%d records scanned)\n", drive, fileCount, pfCount, dirCount, usnRecords)
	return foundFiles, foundDirs, cleanerIni, nil
}

func queryUSNJournal(drive string) (usnJournalDataV0, error) {
	var journal usnJournalDataV0
	h, err := winapi.OpenVolumeHandle(drive)
	if err != nil {
		return journal, err
	}
	defer windows.CloseHandle(h)

	var bytesReturned uint32
	if err := winapi.DeviceIoControl(
		h,
		fsctlQueryUSNJournal,
		nil,
		0,
		unsafe.Pointer(&journal),
		uint32(unsafe.Sizeof(journal)),
		&bytesReturned,
	); err != nil {
		return journal, err
	}
	return journal, nil
}

// PathResolver builds and memoizes full NTFS paths from FRN -> parent chains.
// It mirrors the approach voidtools Everything uses: walk the MFT parent chain
// once per FRN and cache the result so repeated lookups (e.g. one per USN
// record) are O(1) map reads instead of repeated chain walks.
type PathResolver struct {
	nodes map[uint64]models.MFTNode
	drive string
	mu    sync.Mutex
	cache map[uint64]string
}

// NewPathResolver wraps a prebuilt node map with a path cache.
func NewPathResolver(nodes map[uint64]models.MFTNode, drive string) *PathResolver {
	return &PathResolver{
		nodes: nodes,
		drive: drive,
		cache: make(map[uint64]string, len(nodes)/4+1),
	}
}

// Nodes returns the underlying node map (read-only intent).
func (r *PathResolver) Nodes() map[uint64]models.MFTNode { return r.nodes }

// Resolve returns the full path for a file reference number, cached after first use.
func (r *PathResolver) Resolve(frn uint64) string {
	r.mu.Lock()
	if p, ok := r.cache[frn]; ok {
		r.mu.Unlock()
		return p
	}
	r.mu.Unlock()

	seen := make(map[uint64]bool, 32)
	parts := make([]string, 0, 16)
	cur := frn
	for {
		if seen[cur] {
			break
		}
		seen[cur] = true
		node, ok := r.nodes[cur]
		if !ok {
			break
		}
		if node.Name != "" {
			parts = append(parts, node.Name)
		}
		if node.Parent == 0 || node.Parent == cur {
			break
		}
		cur = node.Parent
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	p := r.drive + `\` + strings.Join(parts, `\`)

	r.mu.Lock()
	if _, dup := r.cache[frn]; !dup {
		r.cache[frn] = p
	}
	r.mu.Unlock()
	return p
}

// IndexDriveFilesMFT enumerates .exe paths via the USN MFT index.
func IndexDriveFilesMFT(drive string) ([]string, map[uint64]models.MFTNode, *PathResolver, error) {
	h, err := winapi.OpenVolumeHandle(drive)
	if err != nil {
		return nil, nil, nil, err
	}
	defer windows.CloseHandle(h)

	journal, err := queryUSNJournal(drive)
	if err != nil {
		return nil, nil, nil, err
	}

	enumData := mftEnumDataV0{
		StartFileReferenceNumber: 0,
		LowUsn:                   0,
		HighUsn:                  journal.NextUsn,
	}
	var bytesReturned uint32
	buffer := make([]byte, 1<<20)
	nodes := make(map[uint64]models.MFTNode, 262144)

	for {
		bytesReturned = 0
		err := winapi.DeviceIoControl(
			h,
			fsctlEnumUSNData,
			unsafe.Pointer(&enumData),
			uint32(unsafe.Sizeof(enumData)),
			unsafe.Pointer(&buffer[0]),
			uint32(len(buffer)),
			&bytesReturned,
		)
		if err != nil {
			if err == windows.ERROR_HANDLE_EOF {
				break
			}
			return nil, nil, nil, err
		}
		if bytesReturned <= 8 {
			break
		}

		nextFRN := *(*uint64)(unsafe.Pointer(&buffer[0]))
		offset := uint32(8)
		for offset+uint32(unsafe.Sizeof(usnRecordV2{})) <= bytesReturned {
			rec := (*usnRecordV2)(unsafe.Pointer(&buffer[offset]))
			if rec.RecordLength == 0 || offset+rec.RecordLength > bytesReturned {
				break
			}
			if rec.FileNameLength > 0 {
				nameStart := offset + uint32(rec.FileNameOffset)
				nameChars := int(rec.FileNameLength / 2)
				namePtr := (*uint16)(unsafe.Pointer(&buffer[nameStart]))
				nameSlice := unsafe.Slice(namePtr, nameChars)
				name := windows.UTF16ToString(nameSlice)
				nodes[rec.FileReferenceNumber] = models.MFTNode{
					Name:   name,
					Parent: rec.ParentFileReferenceNum,
					IsDir:  rec.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
				}
			}
			offset += rec.RecordLength
		}
		enumData.StartFileReferenceNumber = nextFRN
	}

	resolver := NewPathResolver(nodes, drive)

	paths := make([]string, 0, len(nodes)/8)
	for frn, node := range nodes {
		if node.IsDir {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(node.Name), ".exe") {
			continue
		}
		paths = append(paths, resolver.Resolve(frn))
	}

	return paths, nodes, resolver, nil
}

// IndexDriveFiles walks the filesystem for .exe files (fallback).
func IndexDriveFiles(root string) []string {
	paths := make([]string, 0, 65536)
	stack := []string{root}

	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			path := filepath.Join(dir, name)
			if entry.IsDir() {
				// Skip junctions/symlinks: they can form cycles.
				if winapi.IsReparsePoint(entry) {
					continue
				}
				stack = append(stack, path)
				continue
			}
			if !strings.HasSuffix(strings.ToLower(name), ".exe") || strings.HasSuffix(name, "~") {
				continue
			}
			paths = append(paths, path)
		}
	}

	return paths
}

// ParseRecycleIFile parses a Recycle-Bin $I metadata file.
func ParseRecycleIFile(iPath string) (models.RecycleInfo, error) {
	b, err := os.ReadFile(iPath)
	if err != nil {
		return models.RecycleInfo{}, err
	}
	if len(b) < 24 {
		return models.RecycleInfo{}, fmt.Errorf("invalid $I file")
	}
	deleteFT := binary.LittleEndian.Uint64(b[16:24])
	ft := windows.Filetime{LowDateTime: uint32(deleteFT), HighDateTime: uint32(deleteFT >> 32)}
	deletedAt := winapi.FiletimeToTime(ft)

	// Version 2 stores path length (bytes) at offset 24; version 1 is null-terminated from offset 24.
	version := b[0]
	if version >= 2 && len(b) >= 28 {
		n := binary.LittleEndian.Uint32(b[24:28])
		remain := uint32(len(b) - 28)
		if n > 0 && n <= remain && n%2 == 0 {
			u16 := make([]uint16, n/2)
			for i := range u16 {
				u16[i] = binary.LittleEndian.Uint16(b[28+i*2:])
			}
			orig := windows.UTF16ToString(u16)
			return models.RecycleInfo{OriginalPath: orig, DeletedAt: deletedAt}, nil
		}
	}

	// Version 1 (or fallback): null-terminated UTF-16 starting at offset 24.
	start := 24
	if start >= len(b) {
		return models.RecycleInfo{OriginalPath: "", DeletedAt: deletedAt}, nil
	}
	u16Count := (len(b) - start) / 2
	u16 := make([]uint16, 0, u16Count)
	for i := 0; i < u16Count; i++ {
		v := binary.LittleEndian.Uint16(b[start+i*2 : start+i*2+2])
		if v == 0 {
			break
		}
		u16 = append(u16, v)
	}
	orig := windows.UTF16ToString(u16)
	return models.RecycleInfo{OriginalPath: orig, DeletedAt: deletedAt}, nil
}

// PrintUSNStatus prints journal status for all drives.
func PrintUSNStatus(drives []string) {
	for _, j := range CollectUSNJournalStatus(drives) {
		if !j.Available {
			fmt.Printf("[USN] %s: unavailable (%s)\n", j.Drive, j.Error)
			continue
		}
		fmt.Printf("[USN] %s: JournalID=%d FirstUSN=%d NextUSN=%d UsnJrnlCreatedAt=%s\n",
			j.Drive, j.JournalID, j.FirstUSN, j.NextUSN, j.CreatedAt.Format("2006-01-02 15:04:05"))
		if j.Wiped {
			fmt.Printf("ПОЧИСТИЛИ USN (%s)\n", j.Drive)
		}
	}
}

// CollectUSNJournalStatus returns structured $UsnJrnl state per drive.
// Wipe detection follows CheckDeletedUSN: if the $UsnJrnl:$J file creation
// timestamp is later than the system boot time, the journal was deleted and
// re-created during this session — i.e. someone wiped it.
func CollectUSNJournalStatus(drives []string) []models.USNJournalInfo {
	bootTime := winapi.GetSystemBootTime()
	out := make([]models.USNJournalInfo, 0, len(drives))
	for _, d := range drives {
		drive := strings.ToUpper(d)
		info := models.USNJournalInfo{Drive: drive, BootTime: bootTime}

		journal, err := queryUSNJournal(drive)
		if err != nil {
			info.Error = err.Error()
			out = append(out, info)
			continue
		}
		info.JournalID = journal.UsnJournalID
		info.FirstUSN = journal.FirstUsn
		info.NextUSN = journal.NextUsn

		createdAt, err := usnJournalCreationTime(drive)
		if err != nil {
			info.Error = err.Error()
			out = append(out, info)
			continue
		}
		info.Available = true
		info.CreatedAt = createdAt
		if createdAt.After(bootTime) {
			info.Wiped = true
		}
		out = append(out, info)
	}
	return out
}

func usnJournalCreationTime(drive string) (time.Time, error) {
	path := drive + `\$Extend\$UsnJrnl:$J`
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return time.Time{}, err
	}
	h, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return time.Time{}, err
	}
	defer windows.CloseHandle(h)

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return time.Time{}, err
	}
	return winapi.FiletimeToTime(info.CreationTime), nil
}

func isTargetDirName(name string, targetDirNames []string) bool {
	for _, n := range targetDirNames {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

func matchesTargetDirPath(path string, targetDirNames []string) bool {
	pl := strings.ToLower(path)
	if strings.Contains(pl, `\$recycle.bin\`) {
		for _, n := range targetDirNames {
			lower := strings.ToLower(n)
			if strings.Contains(pl, `\`+lower+`\`) || strings.HasSuffix(pl, `\`+lower) {
				return true
			}
		}
	}
	for _, n := range targetDirNames {
		lower := strings.ToLower(n)
		if strings.Contains(pl, `\`+lower+`\`) || strings.HasSuffix(pl, `\`+lower) {
			return true
		}
	}
	return false
}

func matchesDeletedPath(path string, rules []models.SearchRule) bool {
	pl := strings.ToLower(path)
	for _, r := range rules {
		if strings.Contains(pl, r.PatternLower) {
			return true
		}
	}
	return false
}
