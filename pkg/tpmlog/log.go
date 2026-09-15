package tpmlog

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
)

// Format 은 이벤트 로그의 레코드 형식이다.
type Format int

const (
	// FormatSHA1 은 TCG 1.2 형식(TCG_PCClientPCREvent, SHA-1 다이제스트 고정)이다.
	FormatSHA1 Format = iota
	// FormatCryptoAgile 은 TCG 2.0 형식(TCG_PCR_EVENT2, 알고리즘별 다이제스트)이다.
	FormatCryptoAgile
)

func (f Format) String() string {
	switch f {
	case FormatCryptoAgile:
		return "crypto-agile (TCG_PCR_EVENT2)"
	default:
		return "legacy SHA-1 (TCG_PCClientPCREvent)"
	}
}

// Digest 는 한 알고리즘의 측정값이다.
type Digest struct {
	Alg   AlgorithmID
	Value []byte
}

func (d Digest) Hex() string { return hex.EncodeToString(d.Value) }

// Event 는 로그의 한 레코드다.
type Event struct {
	// Sequence 는 로그 내 0부터 시작하는 순번이다.
	Sequence int
	// Offset 은 파일 내 레코드 시작 오프셋이다.
	Offset   int
	PCRIndex uint32
	Type     EventType
	Digests  []Digest
	// Data 는 원본 이벤트 데이터(디코딩 전)다.
	Data []byte

	decoded EventData
}

// Digest 는 지정한 알고리즘의 다이제스트를 찾는다.
func (e *Event) Digest(alg AlgorithmID) (Digest, bool) {
	for _, d := range e.Digests {
		if d.Alg == alg {
			return d, true
		}
	}
	return Digest{}, false
}

// Decoded 는 이벤트 데이터를 종류에 맞게 해석한 결과를 반환한다.
// 해석에 실패하거나 구조가 정의되지 않은 경우 RawData 를 돌려준다.
func (e *Event) Decoded() EventData {
	if e.decoded == nil {
		e.decoded = decodeEventData(e.Type, e.Data)
	}
	return e.decoded
}

// Log 는 파싱된 TCG 이벤트 로그 전체다.
type Log struct {
	Format Format
	// SpecID 는 crypto-agile 로그의 헤더 이벤트다. legacy 로그면 nil.
	SpecID *SpecIDEvent
	Events []Event
	// TrailingBytes 는 마지막 유효 레코드 뒤에 남은 바이트 수다(보통 파일 패딩).
	TrailingBytes int
	// ParseError 는 로그가 중간에서 끊겼을 때의 원인이다.
	// 이 경우에도 Events 에는 그 지점까지 읽은 레코드가 담긴다.
	ParseError error
}

// specIDSignature 는 TCG_EfiSpecIdEvent 의 시그니처다("Spec ID Event03\0").
var specIDSignature = []byte("Spec ID Event03\x00")

// Parse 는 WBCL/TCG 이벤트 로그 바이트열을 파싱한다.
//
// 로그가 중간에 손상되어도 그 지점까지의 이벤트를 담은 Log 를 반환하며,
// 이때 Log.ParseError 가 설정된다(반환 error 는 nil 이 아니다).
func Parse(data []byte) (*Log, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty log")
	}

	l := &Log{Format: FormatSHA1}

	// 첫 레코드는 두 형식 모두 SHA-1 헤더 레이아웃이다.
	// 이벤트 데이터가 Spec ID Event03 이면 이후 레코드는 crypto-agile 형식이다.
	head := &cursor{b: data}
	first, err := parseSHA1Event(head, 0)
	if err != nil {
		return nil, fmt.Errorf("first event: %w", err)
	}
	if spec, ok := parseSpecIDEvent(first.Data); ok {
		l.Format = FormatCryptoAgile
		l.SpecID = spec
	}

	sizes := l.digestSizes()
	c := &cursor{b: data}

	for {
		if c.remaining() == 0 {
			break
		}
		// 남은 바이트가 전부 0x00/0xFF 면 파일 끝 패딩이다.
		// (WBCL 은 고정 크기 버퍼로 기록되어 뒤쪽이 0 으로 남는 경우가 흔하다.
		//  0 으로만 된 바이트열은 pcr=0/type=0/digest 0개/size=0 인 유효 레코드처럼
		//  보이므로 파싱 전에 걸러내야 한다.)
		if c.isPadding() {
			l.TrailingBytes = c.remaining()
			break
		}

		off := c.off
		var ev Event
		if l.Format == FormatCryptoAgile && len(l.Events) > 0 {
			ev, err = parseEvent2(c, off, sizes)
		} else {
			ev, err = parseSHA1Event(c, off)
		}
		if err != nil {
			if c.isPaddingFrom(off) {
				l.TrailingBytes = len(data) - off
				break
			}
			l.ParseError = fmt.Errorf("event #%d at offset %d: %w", len(l.Events), off, err)
			return l, l.ParseError
		}
		ev.Sequence = len(l.Events)
		l.Events = append(l.Events, ev)
	}

	return l, nil
}

// isPaddingFrom 은 off 이후 전체가 패딩인지 확인한다.
func (c *cursor) isPaddingFrom(off int) bool {
	tmp := cursor{b: c.b, off: off}
	return tmp.isPadding()
}

// parseSHA1Event 은 TCG_PCClientPCREvent 를 읽는다.
func parseSHA1Event(c *cursor, off int) (Event, error) {
	ev := Event{Offset: off}

	pcr, err := c.u32()
	if err != nil {
		return ev, err
	}
	typ, err := c.u32()
	if err != nil {
		return ev, err
	}
	dg, err := c.bytes(AlgSHA1.Size())
	if err != nil {
		return ev, err
	}
	size, err := c.u32()
	if err != nil {
		return ev, err
	}
	data, err := c.bytes(int(size))
	if err != nil {
		return ev, fmt.Errorf("event data (size=%d): %w", size, err)
	}

	ev.PCRIndex = pcr
	ev.Type = EventType(typ)
	ev.Digests = []Digest{{Alg: AlgSHA1, Value: dg}}
	ev.Data = data
	return ev, nil
}

// parseEvent2 는 TCG_PCR_EVENT2 를 읽는다.
func parseEvent2(c *cursor, off int, sizes map[AlgorithmID]int) (Event, error) {
	ev := Event{Offset: off}

	pcr, err := c.u32()
	if err != nil {
		return ev, err
	}
	typ, err := c.u32()
	if err != nil {
		return ev, err
	}
	count, err := c.u32()
	if err != nil {
		return ev, err
	}
	// TPML_DIGEST_VALUES 의 count 상한은 TPM_NUM_PCR_BANKS 수준이다.
	// 비정상적으로 큰 값이면 형식이 어긋난 것으로 본다.
	if count > 16 {
		return ev, fmt.Errorf("implausible digest count %d", count)
	}

	digests := make([]Digest, 0, count)
	for i := uint32(0); i < count; i++ {
		algID, err := c.u16()
		if err != nil {
			return ev, fmt.Errorf("digest %d: %w", i, err)
		}
		alg := AlgorithmID(algID)
		n, ok := sizes[alg]
		if !ok || n == 0 {
			n = alg.Size()
		}
		if n == 0 {
			return ev, fmt.Errorf("digest %d: unknown digest size for %s", i, alg)
		}
		val, err := c.bytes(n)
		if err != nil {
			return ev, fmt.Errorf("digest %d (%s): %w", i, alg, err)
		}
		digests = append(digests, Digest{Alg: alg, Value: val})
	}

	size, err := c.u32()
	if err != nil {
		return ev, err
	}
	data, err := c.bytes(int(size))
	if err != nil {
		return ev, fmt.Errorf("event data (size=%d): %w", size, err)
	}

	ev.PCRIndex = pcr
	ev.Type = EventType(typ)
	ev.Digests = digests
	ev.Data = data
	return ev, nil
}

// digestSizes 는 알고리즘별 다이제스트 길이 표를 만든다.
// crypto-agile 로그면 헤더에 선언된 값을 우선 사용한다.
func (l *Log) digestSizes() map[AlgorithmID]int {
	sizes := make(map[AlgorithmID]int, len(algSizes))
	for alg, n := range algSizes {
		sizes[alg] = n
	}
	if l.SpecID != nil {
		for _, ds := range l.SpecID.DigestSizes {
			if ds.DigestSize > 0 && ds.DigestSize <= 64 {
				sizes[ds.AlgorithmID] = int(ds.DigestSize)
			}
		}
	}
	return sizes
}

// Algorithms 는 로그에 실제로 등장하는 알고리즘 목록을 ID 순으로 반환한다.
func (l *Log) Algorithms() []AlgorithmID {
	seen := map[AlgorithmID]bool{}
	var out []AlgorithmID
	for i := range l.Events {
		for _, d := range l.Events[i].Digests {
			if !seen[d.Alg] {
				seen[d.Alg] = true
				out = append(out, d.Alg)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PCRs 는 로그에 등장하는 PCR 인덱스를 오름차순으로 반환한다.
func (l *Log) PCRs() []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for i := range l.Events {
		if !seen[l.Events[i].PCRIndex] {
			seen[l.Events[i].PCRIndex] = true
			out = append(out, l.Events[i].PCRIndex)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// EventsForPCR 은 특정 PCR 의 이벤트만 골라낸다.
func (l *Log) EventsForPCR(pcr uint32) []*Event {
	var out []*Event
	for i := range l.Events {
		if l.Events[i].PCRIndex == pcr {
			out = append(out, &l.Events[i])
		}
	}
	return out
}

// SpecIDEvent 는 crypto-agile 로그의 헤더(TCG_EfiSpecIdEvent)다.
type SpecIDEvent struct {
	Signature        string
	PlatformClass    uint32
	SpecVersionMinor uint8
	SpecVersionMajor uint8
	SpecErrata       uint8
	UintnSize        uint8
	DigestSizes      []SpecIDDigestSize
	VendorInfo       []byte
}

// SpecIDDigestSize 는 헤더가 선언한 알고리즘/길이 쌍이다.
type SpecIDDigestSize struct {
	AlgorithmID AlgorithmID
	DigestSize  uint16
}

func (s *SpecIDEvent) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s: spec %d.%02d errata %d, platformClass=%d, uintnSize=%d, algorithms=[",
		s.Signature, s.SpecVersionMajor, s.SpecVersionMinor, s.SpecErrata, s.PlatformClass, s.UintnSize)
	for i, ds := range s.DigestSizes {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s(%d)", ds.AlgorithmID, ds.DigestSize)
	}
	b.WriteByte(']')
	if len(s.VendorInfo) > 0 {
		fmt.Fprintf(&b, ", vendorInfo=%s", hex.EncodeToString(s.VendorInfo))
	}
	return b.String()
}

// parseSpecIDEvent 는 이벤트 데이터가 TCG_EfiSpecIdEvent 인지 확인하고 파싱한다.
func parseSpecIDEvent(data []byte) (*SpecIDEvent, bool) {
	if len(data) < len(specIDSignature) || !bytes.Equal(data[:len(specIDSignature)], specIDSignature) {
		return nil, false
	}
	c := &cursor{b: data, off: len(specIDSignature)}

	s := &SpecIDEvent{Signature: "Spec ID Event03"}
	var err error
	if s.PlatformClass, err = c.u32(); err != nil {
		return nil, false
	}
	if s.SpecVersionMinor, err = c.u8(); err != nil {
		return nil, false
	}
	if s.SpecVersionMajor, err = c.u8(); err != nil {
		return nil, false
	}
	if s.SpecErrata, err = c.u8(); err != nil {
		return nil, false
	}
	if s.UintnSize, err = c.u8(); err != nil {
		return nil, false
	}
	count, err := c.u32()
	if err != nil || count > 16 {
		return nil, false
	}
	for i := uint32(0); i < count; i++ {
		algID, err := c.u16()
		if err != nil {
			return nil, false
		}
		size, err := c.u16()
		if err != nil {
			return nil, false
		}
		s.DigestSizes = append(s.DigestSizes, SpecIDDigestSize{AlgorithmID: AlgorithmID(algID), DigestSize: size})
	}
	vendorSize, err := c.u8()
	if err != nil {
		return nil, false
	}
	if vi, err := c.bytes(int(vendorSize)); err == nil {
		s.VendorInfo = vi
	}
	return s, true
}
