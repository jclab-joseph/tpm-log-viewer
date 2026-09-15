package tpmlog

import (
	"encoding/binary"
	"fmt"
)

// GUID 는 EFI_GUID(혼합 엔디안) 원본 16바이트다.
type GUID [16]byte

func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(g[0:4]),
		binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]),
		g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
}

// 자주 등장하는 UEFI 변수 벤더 GUID.
var guidNames = map[string]string{
	"8be4df61-93ca-11d2-aa0d-00e098032b8c": "EFI_GLOBAL_VARIABLE",
	"d719b2cb-3d3a-4596-a3bc-dad00e67656f": "EFI_IMAGE_SECURITY_DATABASE",
	"77fa9abd-0359-4d32-bd60-28f4e78f784b": "MICROSOFT_VENDOR",
	"605dab50-e046-4300-abb6-3dd810dd8b23": "SHIM_LOCK",
	"4c19049f-4137-4dd3-9c10-8b97a83ffdfa": "EFI_MEMORY_TYPE_INFORMATION",
	"eb9d2d31-2d88-11d3-9a16-0090273fc14d": "SMBIOS_TABLE",
	"eb9d2d30-2d88-11d3-9a16-0090273fc14d": "ACPI_10_TABLE",
	"8868e871-e4f1-11d3-bc22-0080c73c8881": "ACPI_20_TABLE",
	"b122a263-3661-4f68-9929-78f8b0d62180": "EFI_RT_PROPERTIES_TABLE",
	"dcfa911d-26eb-469f-a220-38b7dc461220": "EFI_MEMORY_ATTRIBUTES_TABLE",
}

// Name 은 알려진 GUID 의 별칭을 반환한다. 모르면 빈 문자열.
func (g GUID) Name() string { return guidNames[g.String()] }

// Describe 는 "guid (ALIAS)" 형태의 표시 문자열이다.
func (g GUID) Describe() string {
	if n := g.Name(); n != "" {
		return g.String() + " (" + n + ")"
	}
	return g.String()
}
