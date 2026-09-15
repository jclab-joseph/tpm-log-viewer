package tpmlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

// --- 합성 로그 빌더 ---

type builder struct{ buf bytes.Buffer }

func (b *builder) u8(v uint8)   { b.buf.WriteByte(v) }
func (b *builder) u16(v uint16) { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *builder) u32(v uint32) { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *builder) u64(v uint64) { binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *builder) raw(v []byte) { b.buf.Write(v) }

func utf16le(s string) []byte {
	var out bytes.Buffer
	for _, r := range utf16.Encode([]rune(s)) {
		binary.Write(&out, binary.LittleEndian, r)
	}
	return out.Bytes()
}

// specIDHeader 는 sha1 + sha256 을 선언하는 헤더 이벤트를 만든다.
func specIDHeader() []byte {
	var d builder
	d.raw(specIDSignature)
	d.u32(0) // platformClass
	d.u8(0)  // minor
	d.u8(2)  // major
	d.u8(0)  // errata
	d.u8(8)  // uintnSize
	d.u32(2) // numberOfAlgorithms
	d.u16(uint16(AlgSHA1))
	d.u16(20)
	d.u16(uint16(AlgSHA256))
	d.u16(32)
	d.u8(0) // vendorInfoSize

	var e builder
	e.u32(0)                   // pcrIndex
	e.u32(uint32(EvNoAction))  // eventType
	e.raw(make([]byte, 20))    // sha1 digest (spec: zeros)
	e.u32(uint32(d.buf.Len())) // eventDataSize
	e.raw(d.buf.Bytes())
	return e.buf.Bytes()
}

// event2 는 sha1/sha256 다이제스트를 가진 TCG_PCR_EVENT2 를 만든다.
func event2(pcr uint32, typ EventType, data []byte) []byte {
	sha1Digest := bytes.Repeat([]byte{byte(pcr)}, 20)
	sha256Digest := sha256.Sum256(data)

	var e builder
	e.u32(pcr)
	e.u32(uint32(typ))
	e.u32(2)
	e.u16(uint16(AlgSHA1))
	e.raw(sha1Digest)
	e.u16(uint16(AlgSHA256))
	e.raw(sha256Digest[:])
	e.u32(uint32(len(data)))
	e.raw(data)
	return e.buf.Bytes()
}

func variableData(guid GUID, name string, value []byte) []byte {
	var d builder
	d.raw(guid[:])
	nameBytes := utf16le(name)
	d.u64(uint64(len(nameBytes) / 2))
	d.u64(uint64(len(value)))
	d.raw(nameBytes)
	d.raw(value)
	return d.buf.Bytes()
}

// filePathDevicePath 는 Media/FilePath 노드 + End 노드로 된 디바이스 패스다.
func filePathDevicePath(path string) []byte {
	name := append(utf16le(path), 0x00, 0x00)
	var d builder
	d.u8(0x04) // Media
	d.u8(0x04) // FilePath
	d.u16(uint16(4 + len(name)))
	d.raw(name)
	d.u8(0x7F) // End
	d.u8(0xFF)
	d.u16(4)
	return d.buf.Bytes()
}

func imageLoadData(base, size, linkTime uint64, devPath []byte) []byte {
	var d builder
	d.u64(base)
	d.u64(size)
	d.u64(linkTime)
	d.u64(uint64(len(devPath)))
	d.raw(devPath)
	return d.buf.Bytes()
}

func taggedEventData(id uint32, payload []byte) []byte {
	var d builder
	d.u32(id)
	d.u32(uint32(len(payload)))
	d.raw(payload)
	return d.buf.Bytes()
}

var globalVarGUID = GUID{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}

func syntheticLog() []byte {
	var b builder
	b.raw(specIDHeader())
	b.raw(event2(0, EvSCRTMVersion, utf16le("Test Firmware 1.0\x00")))
	b.raw(event2(7, EvEFIVariableDriverConfig, variableData(globalVarGUID, "SecureBoot", []byte{0x01})))
	b.raw(event2(4, EvEFIBootServicesApplication,
		imageLoadData(0x7f000000, 0x9c000, 0x140000000, filePathDevicePath(`\EFI\Microsoft\Boot\bootmgfw.efi`))))
	b.raw(event2(12, EvEventTag, taggedEventData(0x00000010, utf16le("BootDebug: 0"))))
	b.raw(event2(4, EvSeparator, []byte{0x00, 0x00, 0x00, 0x00}))
	b.raw(make([]byte, 64)) // 파일 끝 패딩
	return b.buf.Bytes()
}

func TestParseCryptoAgile(t *testing.T) {
	log, err := Parse(syntheticLog())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if log.Format != FormatCryptoAgile {
		t.Errorf("Format = %v, want crypto-agile", log.Format)
	}
	if log.SpecID == nil {
		t.Fatal("SpecID is nil")
	}
	if got, want := len(log.SpecID.DigestSizes), 2; got != want {
		t.Errorf("DigestSizes = %d, want %d", got, want)
	}
	if got, want := len(log.Events), 6; got != want {
		t.Fatalf("events = %d, want %d", got, want)
	}
	if log.TrailingBytes != 64 {
		t.Errorf("TrailingBytes = %d, want 64", log.TrailingBytes)
	}

	// 헤더 이벤트는 SHA-1 레코드 하나만 갖는다.
	if got := len(log.Events[0].Digests); got != 1 {
		t.Errorf("header digests = %d, want 1", got)
	}
	if _, ok := log.Events[0].Decoded().(*SpecIDEvent); !ok {
		t.Errorf("header decoded as %T, want *SpecIDEvent", log.Events[0].Decoded())
	}

	// 이후 이벤트는 sha1 + sha256 을 갖는다.
	if got := len(log.Events[1].Digests); got != 2 {
		t.Errorf("event digests = %d, want 2", got)
	}
	if txt, ok := log.Events[1].Decoded().(TextData); !ok || txt.Text != "Test Firmware 1.0" {
		t.Errorf("EV_S_CRTM_VERSION decoded = %#v", log.Events[1].Decoded())
	}

	v, ok := log.Events[2].Decoded().(*UEFIVariableData)
	if !ok {
		t.Fatalf("variable event decoded as %T", log.Events[2].Decoded())
	}
	if v.UnicodeName != "SecureBoot" || len(v.VariableData) != 1 || v.VariableData[0] != 1 {
		t.Errorf("variable = %+v", v)
	}
	if v.VariableName.Name() != "EFI_GLOBAL_VARIABLE" {
		t.Errorf("guid name = %q, want EFI_GLOBAL_VARIABLE", v.VariableName.Name())
	}

	img, ok := log.Events[3].Decoded().(ImageLoadEvent)
	if !ok {
		t.Fatalf("image event decoded as %T", log.Events[3].Decoded())
	}
	if img.ImageLocationInMemory != 0x7f000000 || img.ImageLengthInMemory != 0x9c000 {
		t.Errorf("image = %+v", img)
	}
	if want := `File(\EFI\Microsoft\Boot\bootmgfw.efi)`; FormatDevicePath(img.DevicePath) != want {
		t.Errorf("device path = %q, want %q", FormatDevicePath(img.DevicePath), want)
	}

	tag, ok := log.Events[4].Decoded().(TaggedEvent)
	if !ok {
		t.Fatalf("tagged event decoded as %T", log.Events[4].Decoded())
	}
	if tag.TaggedEventID != 0x10 {
		t.Errorf("taggedEventID = 0x%X, want 0x10", tag.TaggedEventID)
	}

	if got, want := log.PCRs(), []uint32{0, 4, 7, 12}; !equalU32(got, want) {
		t.Errorf("PCRs = %v, want %v", got, want)
	}
	if got, want := log.Algorithms(), []AlgorithmID{AlgSHA1, AlgSHA256}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Algorithms = %v, want %v", got, want)
	}
}

func TestParseLegacySHA1(t *testing.T) {
	// 헤더 없이 SHA-1 레코드만 있는 로그.
	var b builder
	b.u32(4)
	b.u32(uint32(EvEFIAction))
	b.raw(bytes.Repeat([]byte{0xAA}, 20))
	action := []byte("Calling EFI Application from Boot Option")
	b.u32(uint32(len(action)))
	b.raw(action)

	log, err := Parse(b.buf.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if log.Format != FormatSHA1 {
		t.Errorf("Format = %v, want legacy SHA-1", log.Format)
	}
	if len(log.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(log.Events))
	}
	if txt, ok := log.Events[0].Decoded().(TextData); !ok || txt.Text != string(action) {
		t.Errorf("decoded = %#v", log.Events[0].Decoded())
	}
}

func TestReplayPCRs(t *testing.T) {
	log, err := Parse(syntheticLog())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	values, err := log.ReplayPCRs(AlgSHA256)
	if err != nil {
		t.Fatalf("ReplayPCRs: %v", err)
	}

	// PCR 4 는 두 이벤트(부트 애플리케이션, 세퍼레이터)가 확장된다.
	var pcr4, pcr0 *PCRValue
	for i := range values {
		switch values[i].PCRIndex {
		case 0:
			pcr0 = &values[i]
		case 4:
			pcr4 = &values[i]
		}
	}
	// 헤더(EV_NO_ACTION)는 확장되지 않으므로 PCR 0 은 EV_S_CRTM_VERSION 1건뿐이다.
	if pcr0 == nil || pcr0.Extends != 1 {
		t.Errorf("PCR 0 replay = %+v, want 1 extend", pcr0)
	}
	if pcr4 == nil {
		t.Fatal("PCR 4 missing from replay")
	}
	if pcr4.Extends != 2 {
		t.Errorf("PCR 4 extends = %d, want 2", pcr4.Extends)
	}

	// 직접 계산한 기대값과 비교.
	want := make([]byte, 32)
	for _, ev := range log.EventsForPCR(4) {
		d, _ := ev.Digest(AlgSHA256)
		h := sha256.New()
		h.Write(want)
		h.Write(d.Value)
		want = h.Sum(nil)
	}
	if !bytes.Equal(pcr4.Value, want) {
		t.Errorf("PCR 4 = %s, want %s", hex.EncodeToString(pcr4.Value), hex.EncodeToString(want))
	}
}

func TestReplayStartupLocality(t *testing.T) {
	var b builder
	b.raw(specIDHeader())
	locality := append([]byte("StartupLocality\x00"), 0x03)
	b.raw(event2(0, EvNoAction, locality))
	b.raw(event2(0, EvPostCode, []byte("POST CODE")))

	log, err := Parse(b.buf.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sl, ok := log.Events[1].Decoded().(StartupLocality); !ok || sl.Locality != 3 {
		t.Fatalf("locality decoded = %#v", log.Events[1].Decoded())
	}

	values, err := log.ReplayPCRs(AlgSHA256)
	if err != nil {
		t.Fatalf("ReplayPCRs: %v", err)
	}
	init := make([]byte, 32)
	init[31] = 3
	d, _ := log.Events[2].Digest(AlgSHA256)
	h := sha256.New()
	h.Write(init)
	h.Write(d.Value)
	want := h.Sum(nil)

	if len(values) != 1 || values[0].PCRIndex != 0 {
		t.Fatalf("replay = %+v", values)
	}
	if !bytes.Equal(values[0].Value, want) {
		t.Errorf("PCR 0 = %s, want %s", hex.EncodeToString(values[0].Value), hex.EncodeToString(want))
	}
}

func TestParseTruncated(t *testing.T) {
	full := syntheticLog()
	// 마지막 레코드 중간에서 자른다(패딩 64바이트 + 몇 바이트 더).
	log, err := Parse(full[:len(full)-70])
	if err == nil {
		t.Fatal("expected a parse error for a truncated log")
	}
	if log == nil {
		t.Fatal("Parse returned nil log; partial events should be preserved")
	}
	if len(log.Events) == 0 {
		t.Error("no events preserved from truncated log")
	}
	if log.ParseError == nil {
		t.Error("ParseError not set")
	}
}

func TestDevicePathHardDrive(t *testing.T) {
	var d builder
	d.u8(0x04)
	d.u8(0x01)
	d.u16(42)
	d.u32(1)                           // PartitionNumber
	d.u64(0x800)                       // PartitionStart
	d.u64(0x32000)                     // PartitionSize
	d.raw(bytes.Repeat([]byte{0}, 16)) // Signature
	d.u8(0x02)                         // MBRType: GPT
	d.u8(0x02)                         // SignatureType: GUID
	d.u8(0x7F)
	d.u8(0xFF)
	d.u16(4)

	got := FormatDevicePath(d.buf.Bytes())
	want := "HD(1,GPT:00000000-0000-0000-0000-000000000000,start=0x800,size=0x32000)"
	if got != want {
		t.Errorf("device path = %q, want %q", got, want)
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
