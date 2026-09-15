package tpmlog

import (
	"encoding/binary"
	"fmt"
)

// cursor 는 리틀엔디안 바이너리 스트림을 경계 검사와 함께 읽는 헬퍼다.
// 반환되는 슬라이스는 원본 버퍼를 그대로 참조한다(복사하지 않음).
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) remaining() int { return len(c.b) - c.off }

func (c *cursor) need(n int) error {
	if n < 0 {
		return fmt.Errorf("offset %d: negative length %d", c.off, n)
	}
	if n > c.remaining() {
		return fmt.Errorf("offset %d: need %d bytes, only %d left", c.off, n, c.remaining())
	}
	return nil
}

func (c *cursor) bytes(n int) ([]byte, error) {
	if err := c.need(n); err != nil {
		return nil, err
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v, nil
}

func (c *cursor) u8() (uint8, error) {
	v, err := c.bytes(1)
	if err != nil {
		return 0, err
	}
	return v[0], nil
}

func (c *cursor) u16() (uint16, error) {
	v, err := c.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(v), nil
}

func (c *cursor) u32() (uint32, error) {
	v, err := c.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(v), nil
}

func (c *cursor) u64() (uint64, error) {
	v, err := c.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(v), nil
}

func (c *cursor) guid() (GUID, error) {
	var g GUID
	v, err := c.bytes(16)
	if err != nil {
		return g, err
	}
	copy(g[:], v)
	return g, nil
}

// isPadding 은 남은 바이트가 전부 0x00 또는 0xFF 인지 확인한다.
// 로그 파일 끝의 패딩을 파싱 오류와 구분하는 데 사용한다.
func (c *cursor) isPadding() bool {
	rest := c.b[c.off:]
	if len(rest) == 0 {
		return true
	}
	first := rest[0]
	if first != 0x00 && first != 0xFF {
		return false
	}
	for _, x := range rest {
		if x != first {
			return false
		}
	}
	return true
}
