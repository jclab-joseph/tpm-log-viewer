package tpmlog

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EventData 는 해석된 이벤트 데이터다. String() 은 한 줄 요약이며,
// Details() 는 필요할 때 여러 줄로 풀어쓴 설명이다(없으면 nil).
type EventData interface {
	String() string
}

// detailer 는 여러 줄 상세 출력을 제공하는 EventData 다.
type detailer interface {
	Details() []string
}

// Details 는 EventData 의 상세 줄 목록을 반환한다(없으면 nil).
func Details(d EventData) []string {
	if v, ok := d.(detailer); ok {
		return v.Details()
	}
	return nil
}

// RawData 는 구조가 정의되지 않았거나 해석에 실패한 이벤트 데이터다.
type RawData struct {
	Bytes  []byte
	Reason string // 해석 실패 사유(있을 때만)
}

func (r RawData) String() string {
	if len(r.Bytes) == 0 {
		return "<empty>"
	}
	s := fmt.Sprintf("%d bytes: %s", len(r.Bytes), hexPreview(r.Bytes, 32))
	if r.Reason != "" {
		s += " (" + r.Reason + ")"
	}
	return s
}

// TextData 는 문자열 형태의 이벤트 데이터(EV_ACTION, EV_EFI_ACTION 등)다.
type TextData struct {
	Text string
}

func (t TextData) String() string { return quoteOneLine(t.Text) }

// StartupLocality 는 EV_NO_ACTION 의 StartupLocality 이벤트다.
type StartupLocality struct {
	Locality uint8
}

func (s StartupLocality) String() string {
	return fmt.Sprintf("StartupLocality: %d", s.Locality)
}

// UEFIVariableData 는 UEFI_VARIABLE_DATA 구조다.
type UEFIVariableData struct {
	VariableName GUID
	UnicodeName  string
	VariableData []byte
	// LoadOption 은 Boot#### 변수인 경우 해석된 EFI_LOAD_OPTION 이다.
	LoadOption *LoadOption
}

func (u UEFIVariableData) String() string {
	s := fmt.Sprintf("variable %q, guid %s, data %d bytes", u.UnicodeName, u.VariableName.Describe(), len(u.VariableData))
	if u.LoadOption != nil {
		s += " -> " + u.LoadOption.String()
	} else if v, ok := shortVariableValue(u.UnicodeName, u.VariableData); ok {
		s += " -> " + v
	}
	return s
}

func (u UEFIVariableData) Details() []string {
	var out []string
	if u.LoadOption != nil {
		out = append(out, u.LoadOption.Details()...)
	}
	if len(u.VariableData) > 0 {
		out = append(out, "data: "+hexPreview(u.VariableData, 64))
	}
	return out
}

// shortVariableValue 는 일부 잘 알려진 변수의 값을 짧게 표시한다.
func shortVariableValue(name string, data []byte) (string, bool) {
	switch name {
	case "SecureBoot", "SetupMode", "AuditMode", "DeployedMode":
		if len(data) == 1 {
			return fmt.Sprintf("%d", data[0]), true
		}
	case "BootOrder":
		var ids []string
		for i := 0; i+1 < len(data); i += 2 {
			ids = append(ids, fmt.Sprintf("Boot%04X", uint16(data[i])|uint16(data[i+1])<<8))
		}
		if len(ids) > 0 {
			return strings.Join(ids, ","), true
		}
	}
	return "", false
}

// LoadOption 은 EFI_LOAD_OPTION(Boot#### 변수의 내용)이다.
type LoadOption struct {
	Attributes         uint32
	FilePathListLength uint16
	Description        string
	FilePathList       []byte
	OptionalData       []byte
}

func (o LoadOption) String() string {
	s := fmt.Sprintf("%q", o.Description)
	if p := FormatDevicePath(o.FilePathList); p != "" {
		s += " " + p
	}
	return s
}

func (o LoadOption) Details() []string {
	out := []string{fmt.Sprintf("attributes: 0x%08X", o.Attributes)}
	if p := FormatDevicePath(o.FilePathList); p != "" {
		out = append(out, "device path: "+p)
	}
	if len(o.OptionalData) > 0 {
		out = append(out, "optional data: "+hexPreview(o.OptionalData, 32))
	}
	return out
}

// ImageLoadEvent 는 UEFI_IMAGE_LOAD_EVENT 구조다.
type ImageLoadEvent struct {
	ImageLocationInMemory uint64
	ImageLengthInMemory   uint64
	ImageLinkTimeAddress  uint64
	LengthOfDevicePath    uint64
	DevicePath            []byte
}

func (i ImageLoadEvent) String() string {
	p := FormatDevicePath(i.DevicePath)
	if p == "" {
		p = "<no device path>"
	}
	return fmt.Sprintf("image at 0x%X (%d bytes), link-time 0x%X: %s",
		i.ImageLocationInMemory, i.ImageLengthInMemory, i.ImageLinkTimeAddress, p)
}

func (i ImageLoadEvent) Details() []string {
	return DevicePathNodes(i.DevicePath)
}

// FirmwareBlob 은 UEFI_PLATFORM_FIRMWARE_BLOB 구조다.
type FirmwareBlob struct {
	BlobBase   uint64
	BlobLength uint64
}

func (f FirmwareBlob) String() string {
	return fmt.Sprintf("firmware blob at 0x%X, length %d", f.BlobBase, f.BlobLength)
}

// FirmwareBlob2 는 UEFI_PLATFORM_FIRMWARE_BLOB2 구조다.
type FirmwareBlob2 struct {
	Description string
	BlobBase    uint64
	BlobLength  uint64
}

func (f FirmwareBlob2) String() string {
	return fmt.Sprintf("firmware blob %q at 0x%X, length %d", f.Description, f.BlobBase, f.BlobLength)
}

// HandoffTables 는 UEFI_HANDOFF_TABLE_POINTERS 구조다.
type HandoffTables struct {
	Tables []HandoffTable
}

// HandoffTable 은 (GUID, 물리주소) 항목이다.
type HandoffTable struct {
	VendorGUID  GUID
	VendorTable uint64
}

func (h HandoffTables) String() string {
	return fmt.Sprintf("%d handoff table(s)", len(h.Tables))
}

func (h HandoffTables) Details() []string {
	out := make([]string, 0, len(h.Tables))
	for _, t := range h.Tables {
		out = append(out, fmt.Sprintf("%s @ 0x%X", t.VendorGUID.Describe(), t.VendorTable))
	}
	return out
}

// GPTEvent 는 UEFI_GPT_DATA 구조다.
type GPTEvent struct {
	Header     GPTHeader
	Partitions []GPTPartition
}

// GPTHeader 는 EFI_PARTITION_TABLE_HEADER 다.
type GPTHeader struct {
	Signature        uint64
	Revision         uint32
	HeaderSize       uint32
	CRC32            uint32
	MyLBA            uint64
	AlternateLBA     uint64
	FirstUsableLBA   uint64
	LastUsableLBA    uint64
	DiskGUID         GUID
	PartitionEntryLB uint64
	NumberOfEntries  uint32
	SizeOfEntry      uint32
	EntryArrayCRC32  uint32
}

// GPTPartition 은 EFI_PARTITION_ENTRY 다.
type GPTPartition struct {
	TypeGUID    GUID
	UniqueGUID  GUID
	StartingLBA uint64
	EndingLBA   uint64
	Attributes  uint64
	Name        string
}

func (g GPTEvent) String() string {
	return fmt.Sprintf("GPT disk %s, %d partition(s)", g.Header.DiskGUID, len(g.Partitions))
}

func (g GPTEvent) Details() []string {
	out := []string{fmt.Sprintf("disk GUID: %s, usable LBA %d-%d",
		g.Header.DiskGUID, g.Header.FirstUsableLBA, g.Header.LastUsableLBA)}
	for i, p := range g.Partitions {
		out = append(out, fmt.Sprintf("part %d: %q type %s, LBA %d-%d, attrs 0x%X",
			i+1, p.Name, partitionTypeName(p.TypeGUID), p.StartingLBA, p.EndingLBA, p.Attributes))
	}
	return out
}

var partitionTypes = map[string]string{
	"c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
	"e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft Reserved",
	"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic Data",
	"de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows Recovery",
	"5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM Metadata",
	"af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM Data",
}

func partitionTypeName(g GUID) string {
	if n, ok := partitionTypes[g.String()]; ok {
		return fmt.Sprintf("%s (%s)", g, n)
	}
	return g.String()
}

// TaggedEvent 는 TCG_PCClientTaggedEvent 구조다.
// Windows 는 PCR 11~14 의 측정을 이 형식(SIPA 이벤트)으로 기록한다.
type TaggedEvent struct {
	TaggedEventID uint32
	Data          []byte
	// Entries 는 데이터가 중첩 TLV 스트림으로 해석된 경우의 하위 항목이다.
	Entries []SIPAEntry
}

func (t TaggedEvent) String() string {
	s := fmt.Sprintf("tagged event 0x%08X, %d bytes", t.TaggedEventID, len(t.Data))
	if len(t.Entries) > 0 {
		return s + fmt.Sprintf(", %d entries", len(t.Entries))
	}
	if txt, ok := decodeText(t.Data); ok {
		return s + fmt.Sprintf(" -> %q", txt)
	}
	if len(t.Data) > 0 && len(t.Data) <= 8 {
		return s + " -> " + hex.EncodeToString(t.Data)
	}
	return s
}

func (t TaggedEvent) Details() []string {
	if len(t.Entries) > 0 {
		return SIPALines(t.Entries, "")
	}
	if len(t.Data) == 0 {
		return nil
	}
	if _, ok := decodeText(t.Data); ok {
		return nil
	}
	return []string{"data: " + hexPreview(t.Data, 64)}
}

// decodeEventData 는 이벤트 종류에 맞는 구조체를 만든다.
func decodeEventData(t EventType, data []byte) EventData {
	switch t {
	case EvNoAction:
		if s, ok := parseSpecIDEvent(data); ok {
			return s
		}
		if s, ok := parseStartupLocality(data); ok {
			return s
		}
		return textOrRaw(data)

	case EvEFIVariableDriverConfig, EvEFIVariableBoot, EvEFIVariableBoot2, EvEFIVariableAuthority:
		return parseUEFIVariableData(t, data)

	case EvEFIBootServicesApplication, EvEFIBootServicesDriver, EvEFIRuntimeServicesDriver:
		return parseImageLoadEvent(data)

	case EvEFIPlatformFirmwareBlob, EvEFISPDMFirmwareBlob:
		return parseFirmwareBlob(data)

	case EvEFIPlatformFirmwareBlob2:
		return parseFirmwareBlob2(data)

	case EvEFIHandoffTables:
		return parseHandoffTables(data)

	case EvEFIGPTEvent, EvEFIGPTEvent2:
		return parseGPTEvent(data)

	case EvEventTag:
		return parseTaggedEvent(data)

	case EvAction, EvEFIAction, EvSCRTMVersion, EvPostCode, EvPostCode2,
		EvOmitBootDeviceEvent, EvEFIHCRTMEvent, EvPlatformConfigFlags:
		return textOrRaw(data)

	case EvSeparator:
		// 보통 UINT32 0x00000000 또는 0xFFFFFFFF, 혹은 "WBCL" 같은 문자열.
		return textOrRaw(data)

	default:
		return textOrRaw(data)
	}
}

func textOrRaw(data []byte) EventData {
	if s, ok := decodeText(data); ok {
		return TextData{Text: s}
	}
	return RawData{Bytes: data}
}

func parseStartupLocality(data []byte) (StartupLocality, bool) {
	const sig = "StartupLocality\x00"
	if len(data) != len(sig)+1 || string(data[:len(sig)]) != sig {
		return StartupLocality{}, false
	}
	return StartupLocality{Locality: data[len(sig)]}, true
}

func parseUEFIVariableData(t EventType, data []byte) EventData {
	c := &cursor{b: data}
	g, err := c.guid()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_VARIABLE_DATA"}
	}
	nameLen, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_VARIABLE_DATA"}
	}
	dataLen, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_VARIABLE_DATA"}
	}
	// UnicodeNameLength 는 문자 수(UINT64) 이므로 바이트로는 2배다.
	if nameLen > uint64(c.remaining()/2) {
		return RawData{Bytes: data, Reason: "bad UnicodeNameLength"}
	}
	nameBytes, err := c.bytes(int(nameLen) * 2)
	if err != nil {
		return RawData{Bytes: data, Reason: err.Error()}
	}
	u := &UEFIVariableData{
		VariableName: g,
		UnicodeName:  decodeUTF16(nameBytes),
	}
	if dataLen > uint64(c.remaining()) {
		// 일부 펌웨어는 데이터 길이를 과장해 기록한다. 남은 바이트만 취한다.
		u.VariableData = c.b[c.off:]
	} else {
		u.VariableData, _ = c.bytes(int(dataLen))
	}
	if (t == EvEFIVariableBoot || t == EvEFIVariableBoot2) && isBootOptionName(u.UnicodeName) {
		if lo, ok := parseLoadOption(u.VariableData); ok {
			u.LoadOption = lo
		}
	}
	return u
}

// isBootOptionName 은 Boot#### / Driver#### 형태인지 본다(BootOrder 는 제외).
func isBootOptionName(name string) bool {
	for _, prefix := range []string{"Boot", "Driver", "SysPrep"} {
		if len(name) == len(prefix)+4 && strings.HasPrefix(name, prefix) {
			for _, c := range name[len(prefix):] {
				if !strings.ContainsRune("0123456789ABCDEFabcdef", c) {
					return false
				}
			}
			return true
		}
	}
	return false
}

func parseLoadOption(data []byte) (*LoadOption, bool) {
	c := &cursor{b: data}
	attrs, err := c.u32()
	if err != nil {
		return nil, false
	}
	fpLen, err := c.u16()
	if err != nil {
		return nil, false
	}
	// Description 은 NUL 로 끝나는 UTF-16 문자열이다.
	start := c.off
	for {
		v, err := c.u16()
		if err != nil {
			return nil, false
		}
		if v == 0 {
			break
		}
	}
	desc := decodeUTF16(c.b[start : c.off-2])
	fp, err := c.bytes(int(fpLen))
	if err != nil {
		return nil, false
	}
	return &LoadOption{
		Attributes:         attrs,
		FilePathListLength: fpLen,
		Description:        desc,
		FilePathList:       fp,
		OptionalData:       c.b[c.off:],
	}, true
}

func parseImageLoadEvent(data []byte) EventData {
	c := &cursor{b: data}
	var i ImageLoadEvent
	var err error
	if i.ImageLocationInMemory, err = c.u64(); err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_IMAGE_LOAD_EVENT"}
	}
	if i.ImageLengthInMemory, err = c.u64(); err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_IMAGE_LOAD_EVENT"}
	}
	if i.ImageLinkTimeAddress, err = c.u64(); err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_IMAGE_LOAD_EVENT"}
	}
	if i.LengthOfDevicePath, err = c.u64(); err != nil {
		return RawData{Bytes: data, Reason: "truncated UEFI_IMAGE_LOAD_EVENT"}
	}
	if i.LengthOfDevicePath > uint64(c.remaining()) {
		i.DevicePath = c.b[c.off:]
	} else {
		i.DevicePath, _ = c.bytes(int(i.LengthOfDevicePath))
	}
	return i
}

func parseFirmwareBlob(data []byte) EventData {
	c := &cursor{b: data}
	base, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob"}
	}
	length, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob"}
	}
	return FirmwareBlob{BlobBase: base, BlobLength: length}
}

func parseFirmwareBlob2(data []byte) EventData {
	c := &cursor{b: data}
	descSize, err := c.u8()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob2"}
	}
	desc, err := c.bytes(int(descSize))
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob2 description"}
	}
	base, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob2"}
	}
	length, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated firmware blob2"}
	}
	return FirmwareBlob2{Description: string(trimNul(desc)), BlobBase: base, BlobLength: length}
}

func parseHandoffTables(data []byte) EventData {
	c := &cursor{b: data}
	count, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated handoff tables"}
	}
	if count > uint64(c.remaining()/24) {
		return RawData{Bytes: data, Reason: "bad NumberOfTables"}
	}
	h := HandoffTables{}
	for i := uint64(0); i < count; i++ {
		g, err := c.guid()
		if err != nil {
			break
		}
		addr, err := c.u64()
		if err != nil {
			break
		}
		h.Tables = append(h.Tables, HandoffTable{VendorGUID: g, VendorTable: addr})
	}
	return h
}

func parseGPTEvent(data []byte) EventData {
	c := &cursor{b: data}
	var h GPTHeader
	var err error
	read := func(dst *uint64) bool { *dst, err = c.u64(); return err == nil }
	read32 := func(dst *uint32) bool { *dst, err = c.u32(); return err == nil }

	if !read(&h.Signature) || !read32(&h.Revision) || !read32(&h.HeaderSize) || !read32(&h.CRC32) {
		return RawData{Bytes: data, Reason: "truncated GPT header"}
	}
	if _, err := c.u32(); err != nil { // Reserved
		return RawData{Bytes: data, Reason: "truncated GPT header"}
	}
	if !read(&h.MyLBA) || !read(&h.AlternateLBA) || !read(&h.FirstUsableLBA) || !read(&h.LastUsableLBA) {
		return RawData{Bytes: data, Reason: "truncated GPT header"}
	}
	if h.DiskGUID, err = c.guid(); err != nil {
		return RawData{Bytes: data, Reason: "truncated GPT header"}
	}
	if !read(&h.PartitionEntryLB) || !read32(&h.NumberOfEntries) || !read32(&h.SizeOfEntry) || !read32(&h.EntryArrayCRC32) {
		return RawData{Bytes: data, Reason: "truncated GPT header"}
	}

	g := GPTEvent{Header: h}
	count, err := c.u64()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated GPT partition count"}
	}
	entrySize := int(h.SizeOfEntry)
	if entrySize < 128 {
		entrySize = 128
	}
	if count > uint64(c.remaining()/entrySize) {
		return RawData{Bytes: data, Reason: "bad NumberOfPartitions"}
	}
	for i := uint64(0); i < count; i++ {
		entry, err := c.bytes(entrySize)
		if err != nil {
			break
		}
		e := &cursor{b: entry}
		var p GPTPartition
		if p.TypeGUID, err = e.guid(); err != nil {
			break
		}
		if p.UniqueGUID, err = e.guid(); err != nil {
			break
		}
		if p.StartingLBA, err = e.u64(); err != nil {
			break
		}
		if p.EndingLBA, err = e.u64(); err != nil {
			break
		}
		if p.Attributes, err = e.u64(); err != nil {
			break
		}
		if name, err := e.bytes(72); err == nil {
			p.Name = decodeUTF16(name)
		}
		g.Partitions = append(g.Partitions, p)
	}
	return g
}

func parseTaggedEvent(data []byte) EventData {
	c := &cursor{b: data}
	id, err := c.u32()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated tagged event"}
	}
	size, err := c.u32()
	if err != nil {
		return RawData{Bytes: data, Reason: "truncated tagged event"}
	}
	payload := c.b[c.off:]
	if size <= uint32(c.remaining()) {
		payload, _ = c.bytes(int(size))
	}
	t := TaggedEvent{TaggedEventID: id, Data: payload}
	// Windows 의 태그 이벤트는 ID 에 컨테이너 비트가 있으면 내용이 다시 TLV 스트림이다.
	if id&sipaContainerFlag != 0 {
		if entries, ok := parseSIPAEntries(payload); ok {
			t.Entries = entries
		}
	}
	return t
}

// hexPreview 는 최대 max 바이트까지 hex 로 표시하고 나머지는 생략 표시한다.
func hexPreview(b []byte, max int) string {
	if len(b) <= max {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:max]) + fmt.Sprintf("... (+%d bytes)", len(b)-max)
}

// quoteOneLine 은 문자열을 따옴표로 감싸 한 줄 표시용으로 만든다.
// 경로처럼 역슬래시가 많은 값이 %q 로 두 번 이스케이프되지 않도록,
// 모호하지 않은 문자열은 그대로 감싼다.
func quoteOneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if printableString(s) && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	return fmt.Sprintf("%q", s)
}
