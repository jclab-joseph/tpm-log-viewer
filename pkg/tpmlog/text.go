package tpmlog

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// decodeUTF16 은 리틀엔디안 UTF-16 바이트열을 문자열로 바꾼다.
// 홀수 바이트가 남으면 버린다.
func decodeUTF16(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// looksUTF16 은 데이터가 UTF-16LE ASCII 문자열처럼 보이는지 판단한다
// (짝수 길이 + 홀수 위치 바이트가 모두 0).
func looksUTF16(b []byte) bool {
	if len(b) < 2 || len(b)%2 != 0 {
		return false
	}
	zeros := 0
	for i := 1; i < len(b); i += 2 {
		if b[i] != 0 {
			return false
		}
		zeros++
	}
	return zeros > 0
}

// printableASCII 은 데이터가 (마지막 NUL 을 제외하고) 출력 가능한 ASCII 인지 본다.
func printableASCII(b []byte) bool {
	b = trimNul(b)
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

func trimNul(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0x00 {
		b = b[:len(b)-1]
	}
	return b
}

// printableString 은 문자열이 전부 출력 가능한 문자인지 본다.
func printableString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '\t' || r == '\r' || r == '\n' || r == ' ' {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// decodeText 는 ASCII/UTF-16 문자열을 추정해 반환한다. 문자열로 보이지 않으면 ok=false.
func decodeText(b []byte) (string, bool) {
	if looksUTF16(b) {
		s := decodeUTF16(b)
		// UINT32 값(예: 0x00000010)도 UTF-16 처럼 보이므로 출력 가능 문자만 허용한다.
		if utf8.ValidString(s) && printableString(s) {
			return s, true
		}
	}
	if printableASCII(b) {
		return string(trimNul(b)), true
	}
	return "", false
}
