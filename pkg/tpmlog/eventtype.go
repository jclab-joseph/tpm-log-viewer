package tpmlog

import "fmt"

// EventType 은 TCG PC Client Platform Firmware Profile 의 이벤트 종류다.
type EventType uint32

const (
	EvPrebootCert         EventType = 0x00000000
	EvPostCode            EventType = 0x00000001
	EvUnused              EventType = 0x00000002
	EvNoAction            EventType = 0x00000003
	EvSeparator           EventType = 0x00000004
	EvAction              EventType = 0x00000005
	EvEventTag            EventType = 0x00000006
	EvSCRTMContents       EventType = 0x00000007
	EvSCRTMVersion        EventType = 0x00000008
	EvCPUMicrocode        EventType = 0x00000009
	EvPlatformConfigFlags EventType = 0x0000000A
	EvTableOfDevices      EventType = 0x0000000B
	EvCompactHash         EventType = 0x0000000C
	EvIPL                 EventType = 0x0000000D
	EvIPLPartitionData    EventType = 0x0000000E
	EvNonhostCode         EventType = 0x0000000F
	EvNonhostConfig       EventType = 0x00000010
	EvNonhostInfo         EventType = 0x00000011
	EvOmitBootDeviceEvent EventType = 0x00000012
	EvPostCode2           EventType = 0x00000013

	EvEFIEventBase               EventType = 0x80000000
	EvEFIVariableDriverConfig    EventType = 0x80000001
	EvEFIVariableBoot            EventType = 0x80000002
	EvEFIBootServicesApplication EventType = 0x80000003
	EvEFIBootServicesDriver      EventType = 0x80000004
	EvEFIRuntimeServicesDriver   EventType = 0x80000005
	EvEFIGPTEvent                EventType = 0x80000006
	EvEFIAction                  EventType = 0x80000007
	EvEFIPlatformFirmwareBlob    EventType = 0x80000008
	EvEFIHandoffTables           EventType = 0x80000009
	EvEFIPlatformFirmwareBlob2   EventType = 0x8000000A
	EvEFIHandoffTables2          EventType = 0x8000000B
	EvEFIVariableBoot2           EventType = 0x8000000C
	EvEFIGPTEvent2               EventType = 0x8000000D
	EvEFIHCRTMEvent              EventType = 0x80000010
	EvEFIVariableAuthority       EventType = 0x800000E0
	EvEFISPDMFirmwareBlob        EventType = 0x800000E1
	EvEFISPDMFirmwareConfig      EventType = 0x800000E2
	EvEFISPDMDevicePolicy        EventType = 0x800000E3
	EvEFISPDMDeviceAuthority     EventType = 0x800000E4
)

var eventTypeNames = map[EventType]string{
	EvPrebootCert:         "EV_PREBOOT_CERT",
	EvPostCode:            "EV_POST_CODE",
	EvUnused:              "EV_UNUSED",
	EvNoAction:            "EV_NO_ACTION",
	EvSeparator:           "EV_SEPARATOR",
	EvAction:              "EV_ACTION",
	EvEventTag:            "EV_EVENT_TAG",
	EvSCRTMContents:       "EV_S_CRTM_CONTENTS",
	EvSCRTMVersion:        "EV_S_CRTM_VERSION",
	EvCPUMicrocode:        "EV_CPU_MICROCODE",
	EvPlatformConfigFlags: "EV_PLATFORM_CONFIG_FLAGS",
	EvTableOfDevices:      "EV_TABLE_OF_DEVICES",
	EvCompactHash:         "EV_COMPACT_HASH",
	EvIPL:                 "EV_IPL",
	EvIPLPartitionData:    "EV_IPL_PARTITION_DATA",
	EvNonhostCode:         "EV_NONHOST_CODE",
	EvNonhostConfig:       "EV_NONHOST_CONFIG",
	EvNonhostInfo:         "EV_NONHOST_INFO",
	EvOmitBootDeviceEvent: "EV_OMIT_BOOT_DEVICE_EVENTS",
	EvPostCode2:           "EV_POST_CODE2",

	EvEFIEventBase:               "EV_EFI_EVENT_BASE",
	EvEFIVariableDriverConfig:    "EV_EFI_VARIABLE_DRIVER_CONFIG",
	EvEFIVariableBoot:            "EV_EFI_VARIABLE_BOOT",
	EvEFIBootServicesApplication: "EV_EFI_BOOT_SERVICES_APPLICATION",
	EvEFIBootServicesDriver:      "EV_EFI_BOOT_SERVICES_DRIVER",
	EvEFIRuntimeServicesDriver:   "EV_EFI_RUNTIME_SERVICES_DRIVER",
	EvEFIGPTEvent:                "EV_EFI_GPT_EVENT",
	EvEFIAction:                  "EV_EFI_ACTION",
	EvEFIPlatformFirmwareBlob:    "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	EvEFIHandoffTables:           "EV_EFI_HANDOFF_TABLES",
	EvEFIPlatformFirmwareBlob2:   "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
	EvEFIHandoffTables2:          "EV_EFI_HANDOFF_TABLES2",
	EvEFIVariableBoot2:           "EV_EFI_VARIABLE_BOOT2",
	EvEFIGPTEvent2:               "EV_EFI_GPT_EVENT2",
	EvEFIHCRTMEvent:              "EV_EFI_HCRTM_EVENT",
	EvEFIVariableAuthority:       "EV_EFI_VARIABLE_AUTHORITY",
	EvEFISPDMFirmwareBlob:        "EV_EFI_SPDM_FIRMWARE_BLOB",
	EvEFISPDMFirmwareConfig:      "EV_EFI_SPDM_FIRMWARE_CONFIG",
	EvEFISPDMDevicePolicy:        "EV_EFI_SPDM_DEVICE_POLICY",
	EvEFISPDMDeviceAuthority:     "EV_EFI_SPDM_DEVICE_AUTHORITY",
}

func (t EventType) String() string {
	if n, ok := eventTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("EV_UNKNOWN(0x%08X)", uint32(t))
}

// PCRDescription 은 PCR 인덱스의 일반적인 용도를 설명한다.
// (PC Client 프로필 + Windows Measured Boot 관례)
func PCRDescription(pcr uint32) string {
	switch pcr {
	case 0:
		return "UEFI firmware code (SRTM, POST code, embedded drivers)"
	case 1:
		return "UEFI firmware configuration / settings"
	case 2:
		return "UEFI driver and application code (option ROMs)"
	case 3:
		return "UEFI driver and application configuration"
	case 4:
		return "UEFI boot manager code and boot attempts"
	case 5:
		return "GPT / partition table, boot manager configuration"
	case 6:
		return "Platform manufacturer specific / resume events"
	case 7:
		return "Secure Boot policy (PK, KEK, db, dbx)"
	case 8, 9:
		return "OS loader measurements (unused on Windows UEFI boot)"
	case 10:
		return "Reserved for OS integrity measurements"
	case 11:
		return "BitLocker access control / Windows boot measurements"
	case 12:
		return "Boot configuration data, boot debug settings"
	case 13:
		return "Boot module details (boot-critical drivers)"
	case 14:
		return "Boot authorities (code integrity signers)"
	case 15:
		return "Windows system integrity / measured OS state"
	case 16:
		return "Debug PCR"
	case 17, 18, 19, 20, 21, 22:
		return "DRTM / trusted OS measurements"
	case 23:
		return "Application support PCR"
	default:
		return "unspecified"
	}
}
