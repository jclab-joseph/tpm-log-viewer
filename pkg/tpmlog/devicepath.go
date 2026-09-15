package tpmlog

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// EFI 디바이스 패스 타입.
const (
	dpTypeHardware  = 0x01
	dpTypeACPI      = 0x02
	dpTypeMessaging = 0x03
	dpTypeMedia     = 0x04
	dpTypeBBS       = 0x05
	dpTypeEnd       = 0x7F
)

// DevicePathNodes 는 EFI_DEVICE_PATH_PROTOCOL 노드들을 사람이 읽을 수 있는
// 문자열 목록으로 변환한다. 구조가 깨지면 읽은 만큼만 반환한다.
func DevicePathNodes(b []byte) []string {
	var out []string
	c := &cursor{b: b}
	for c.remaining() >= 4 {
		typ, err := c.u8()
		if err != nil {
			break
		}
		sub, err := c.u8()
		if err != nil {
			break
		}
		length, err := c.u16()
		if err != nil {
			break
		}
		if length < 4 {
			out = append(out, fmt.Sprintf("Invalid(type=0x%02X,sub=0x%02X,len=%d)", typ, sub, length))
			break
		}
		body, err := c.bytes(int(length) - 4)
		if err != nil {
			out = append(out, fmt.Sprintf("Truncated(type=0x%02X,sub=0x%02X,len=%d)", typ, sub, length))
			break
		}
		if typ == dpTypeEnd {
			if sub == 0x01 { // End of this instance, 다음 인스턴스가 이어진다
				out = append(out, "|")
				continue
			}
			break
		}
		out = append(out, devicePathNode(typ, sub, body))
	}
	return out
}

// FormatDevicePath 는 디바이스 패스를 "/" 로 이어붙인 한 줄 문자열이다.
func FormatDevicePath(b []byte) string {
	nodes := DevicePathNodes(b)
	if len(nodes) == 0 {
		return ""
	}
	return strings.Join(nodes, "/")
}

func devicePathNode(typ, sub uint8, b []byte) string {
	switch typ {
	case dpTypeHardware:
		switch sub {
		case 0x01:
			if len(b) >= 2 {
				return fmt.Sprintf("Pci(0x%X,0x%X)", b[1], b[0]) // Device, Function
			}
		case 0x02:
			if len(b) >= 2 {
				return fmt.Sprintf("PcCard(0x%X)", b[0])
			}
		case 0x03:
			if len(b) >= 20 {
				return fmt.Sprintf("MemoryMapped(0x%X,0x%X-0x%X)",
					le32(b[0:4]), le64(b[4:12]), le64(b[12:20]))
			}
		case 0x04:
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("VenHw(%s)", g)
			}
		case 0x05:
			if len(b) >= 4 {
				return fmt.Sprintf("Ctrl(0x%X)", le32(b[0:4]))
			}
		case 0x06:
			if len(b) >= 4 {
				return fmt.Sprintf("BMC(0x%X)", b[0])
			}
		}

	case dpTypeACPI:
		switch sub {
		case 0x01:
			if len(b) >= 8 {
				return fmt.Sprintf("Acpi(%s,0x%X)", eisaID(le32(b[0:4])), le32(b[4:8]))
			}
		case 0x02:
			if len(b) >= 12 {
				return fmt.Sprintf("AcpiEx(%s,0x%X)", eisaID(le32(b[0:4])), le32(b[4:8]))
			}
		case 0x03:
			if len(b) >= 4 {
				return fmt.Sprintf("AcpiAdr(0x%X)", le32(b[0:4]))
			}
		}

	case dpTypeMessaging:
		switch sub {
		case 0x01:
			if len(b) >= 4 {
				return fmt.Sprintf("Ata(%d,%d,%d)", b[0], b[1], le16(b[2:4]))
			}
		case 0x02:
			if len(b) >= 4 {
				return fmt.Sprintf("Scsi(%d,%d)", le16(b[0:2]), le16(b[2:4]))
			}
		case 0x05:
			if len(b) >= 2 {
				return fmt.Sprintf("Usb(0x%X,0x%X)", b[0], b[1])
			}
		case 0x0B:
			return "MAC(" + hex.EncodeToString(trimNul(b)) + ")"
		case 0x0C:
			return "IPv4"
		case 0x0D:
			return "IPv6"
		case 0x0F:
			return "UsbClass"
		case 0x12:
			if len(b) >= 6 {
				return fmt.Sprintf("Sata(0x%X,0x%X,0x%X)", le16(b[0:2]), le16(b[2:4]), le16(b[4:6]))
			}
		case 0x13:
			return "iSCSI"
		case 0x17:
			if len(b) >= 12 {
				return fmt.Sprintf("NVMe(0x%X,%s)", le32(b[0:4]), hex.EncodeToString(b[4:12]))
			}
		case 0x18:
			return "Uri(" + string(trimNul(b)) + ")"
		case 0x1F:
			return "DNS"
		case 0x20:
			if len(b) >= 16 {
				return fmt.Sprintf("NVDIMM(%s)", hex.EncodeToString(b[:16]))
			}
		case 0x22:
			if len(b) >= 6 {
				return fmt.Sprintf("UFS(0x%X)", b[0])
			}
		}

	case dpTypeMedia:
		switch sub {
		case 0x01: // HARDDRIVE_DEVICE_PATH
			if len(b) >= 38 {
				sigType := b[37]
				sig := "?"
				switch sigType {
				case 0x01:
					sig = fmt.Sprintf("MBR:0x%X", le32(b[20:24]))
				case 0x02:
					var g GUID
					copy(g[:], b[20:36])
					sig = "GPT:" + g.String()
				case 0x00:
					sig = "none"
				}
				return fmt.Sprintf("HD(%d,%s,start=0x%X,size=0x%X)",
					le32(b[0:4]), sig, le64(b[4:12]), le64(b[12:20]))
			}
		case 0x02: // CDROM
			if len(b) >= 20 {
				return fmt.Sprintf("CDROM(0x%X)", le32(b[0:4]))
			}
		case 0x03:
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("VenMedia(%s)", g)
			}
		case 0x04: // FILEPATH
			return "File(" + decodeUTF16(b) + ")"
		case 0x05:
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("Media(%s)", g)
			}
		case 0x06: // PIWG firmware file
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("FvFile(%s)", g)
			}
		case 0x07: // PIWG firmware volume
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("Fv(%s)", g)
			}
		case 0x08: // MEDIA_RELATIVE_OFFSET_RANGE: Reserved UINT32 + start/end UINT64
			if len(b) >= 20 {
				return fmt.Sprintf("Offset(0x%X,0x%X)", le64(b[4:12]), le64(b[12:20]))
			}
		case 0x09:
			if len(b) >= 16 {
				var g GUID
				copy(g[:], b[:16])
				return fmt.Sprintf("RamDisk(%s)", g)
			}
		}

	case dpTypeBBS:
		// BBS_BBS_DEVICE_PATH: DeviceType UINT16 + StatusFlag UINT16 + 설명 문자열
		if sub == 0x01 && len(b) >= 4 {
			return fmt.Sprintf("BBS(0x%X,%s)", le16(b[0:2]), string(trimNul(b[4:])))
		}
	}

	// 알 수 없는 노드는 원본을 그대로 노출한다.
	if len(b) == 0 {
		return fmt.Sprintf("Path(%02X,%02X)", typ, sub)
	}
	return fmt.Sprintf("Path(%02X,%02X,%s)", typ, sub, hexPreview(b, 16))
}

// eisaID 는 ACPI _HID 값을 "PNP0A03" 형태로 표현한다.
func eisaID(v uint32) string {
	if v&0xFFFF == 0x41D0 { // 'PNP'
		return fmt.Sprintf("PNP%04X", v>>16)
	}
	c1 := byte((v & 0x1F)) + 'A' - 1
	c2 := byte((v>>5)&0x1F) + 'A' - 1
	c3 := byte((v>>10)&0x1F) + 'A' - 1
	if isUpperAZ(c1) && isUpperAZ(c2) && isUpperAZ(c3) {
		return fmt.Sprintf("%c%c%c%04X", c1, c2, c3, v>>16)
	}
	return fmt.Sprintf("0x%X", v)
}

func isUpperAZ(c byte) bool { return c >= 'A' && c <= 'Z' }

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
