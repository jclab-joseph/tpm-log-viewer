package tpmlog

import (
	"encoding/binary"
	"fmt"
)

// Windows 는 PCR 11~14 의 측정을 EV_EVENT_TAG 안의 TLV 스트림으로 기록한다
// (WBCL 의 이른바 SIPA 이벤트). 각 항목은 {UINT32 ID, UINT32 크기, 데이터} 이고,
// ID 에 컨테이너 비트가 설정되어 있으면 데이터 자체가 다시 TLV 스트림이다.
//
// ID 별 의미는 Microsoft 내부 정의라 이름표를 붙이지 않고 ID 와 값만 노출한다.
const sipaContainerFlag = 0x40000000

// SIPAEntry 는 태그 이벤트 안의 TLV 항목 하나다.
type SIPAEntry struct {
	ID   uint32
	Data []byte
	// Children 은 컨테이너 항목의 하위 항목이다.
	Children []SIPAEntry
}

// IsContainer 는 항목이 하위 항목을 담는 컨테이너인지 나타낸다.
func (e SIPAEntry) IsContainer() bool { return e.ID&sipaContainerFlag != 0 }

func (e SIPAEntry) String() string {
	if len(e.Children) > 0 {
		return fmt.Sprintf("SIPA(0x%08X) container, %d entries", e.ID, len(e.Children))
	}
	return fmt.Sprintf("SIPA(0x%08X) %d bytes: %s", e.ID, len(e.Data), sipaValue(e.Data))
}

// parseSIPAEntries 는 TLV 스트림을 읽는다.
// 스트림이 버퍼 끝과 정확히 맞아떨어지지 않으면 ok=false 를 반환한다
// (형식 가정이 틀린 경우이므로 호출자는 원본 바이트를 그대로 보여주면 된다).
func parseSIPAEntries(b []byte) ([]SIPAEntry, bool) {
	var out []SIPAEntry
	c := &cursor{b: b}
	for c.remaining() > 0 {
		id, err := c.u32()
		if err != nil {
			return nil, false
		}
		size, err := c.u32()
		if err != nil {
			return nil, false
		}
		data, err := c.bytes(int(size))
		if err != nil {
			return nil, false
		}
		e := SIPAEntry{ID: id, Data: data}
		if e.IsContainer() && len(data) > 0 {
			if kids, ok := parseSIPAEntries(data); ok {
				e.Children = kids
			}
		}
		out = append(out, e)
	}
	return out, len(out) > 0
}

// SIPALines 는 항목 트리를 들여쓰기된 줄 목록으로 펼친다.
func SIPALines(entries []SIPAEntry, indent string) []string {
	var out []string
	for _, e := range entries {
		out = append(out, indent+e.String())
		out = append(out, SIPALines(e.Children, indent+"  ")...)
	}
	return out
}

// sipaValue 는 항목 값을 사람이 읽을 수 있게 표현한다.
// 고정 폭(1/2/4/8바이트)이면 수치로, 그 밖에는 문자열 또는 hex 로 보여준다.
func sipaValue(b []byte) string {
	if len(b) == 0 {
		return "<empty>"
	}
	text, isText := decodeText(b)

	var num string
	switch len(b) {
	case 1:
		num = fmt.Sprintf("0x%02X (%d)", b[0], b[0])
	case 2:
		v := binary.LittleEndian.Uint16(b)
		num = fmt.Sprintf("0x%04X (%d)", v, v)
	case 4:
		v := binary.LittleEndian.Uint32(b)
		num = fmt.Sprintf("0x%08X (%d)", v, v)
	case 8:
		v := binary.LittleEndian.Uint64(b)
		num = fmt.Sprintf("0x%016X (%d)", v, v)
	}
	if num != "" {
		// 수치가 우연히 문자열로도 해석되면 둘 다 보여준다.
		if isText && len([]rune(text)) >= 4 {
			return num + " " + quoteOneLine(text)
		}
		return num
	}
	if isText {
		return quoteOneLine(text)
	}
	return hexPreview(b, 48)
}
