/*++

Copyright (c) 1992  Microsoft Corporation

Module Name:

    spti.h

Abstract:

    These are the structures and defines that are used in the
    SPTI.C. 

Author:

Revision History:

--*/

#pragma warning(disable:4200) /* array[0] is not a warning for this file */
#pragma warning(disable:4214) /* nonstandard extension used : bit field types other than int */

#define SPT_CDB_LENGTH 32
#define SPT_SENSE_LENGTH 32
#define SPTWB_DATA_LENGTH 4096

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
    SCSI_PASS_THROUGH spt;
    ULONG             Filler;      /* realign buffers to double word boundary */
    UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
    UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];
    } SCSI_PASS_THROUGH_WITH_BUFFERS, *PSCSI_PASS_THROUGH_WITH_BUFFERS;
    
typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS_EX {
    SCSI_PASS_THROUGH_EX spt;
    UCHAR             ucCdbBuf[SPT_CDB_LENGTH-1];       /* cushion for spt.Cdb */
    ULONG             Filler;      /* realign buffers to double word boundary */
    STOR_ADDR_BTL8    StorAddress;
    UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
    UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];     /* buffer for DataIn or DataOut */
} SCSI_PASS_THROUGH_WITH_BUFFERS_EX, *PSCSI_PASS_THROUGH_WITH_BUFFERS_EX;

#pragma pack(push)
#pragma pack(1)
typedef struct _SECURITY_PROTOCOL_COMPLIANCE {
    UINT32 PageLength; // Network Byte Order
#if !defined(__midl)
    UCHAR Descriptor[0];
#endif
} SECURITY_PROTOCOL_COMPLIANCE, *PSECURITY_PROTOCOL_COMPLIANCE;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _SECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR {
    UINT16 DescriptorType; /* Network Byte Order */
    UCHAR Reserved1[2];
    UINT32 DescriptorLength; /* Network Byte Order */
#if !defined(__midl)
    UCHAR DescriptorInformation[0];
#endif
} SECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR, *PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR;
#pragma pack(pop)

typedef struct _SECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR_INFO_FIPS140 {
    UCHAR Revision;
    UCHAR OverallSecurityLevel;
    UCHAR Reserved2[6];
    UCHAR HardwareVersion[128];
    UCHAR SoftwareVersion[128];
    UCHAR ModuleName[256];
} SECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR_INFO_FIPS140, *PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR_INFO_FIPS140;

#pragma pack(push)
#pragma pack(1)
typedef struct _DATA_ENCRYPTION_STATUS {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UCHAR KeyScope : 3; /* LSb of [4] */
    UCHAR Reserved1 : 2;
    UCHAR ItNexusScope : 3; /* MSb of [4] */
    UCHAR EncryptionMode;
    UCHAR DecryptionMode;
    UCHAR AlgorithmIndex;
    UINT32 KeyInstanceCounter; /* Network Byte Order */
    UCHAR RawDecryptionModeDisabled : 1; /* LSb of [12] */
    UCHAR CheckExternalEncryptionModeStatus : 2;
    UCHAR VolumeContainsEncryptedLogicalBlocks : 1;
    UCHAR ParametersControl : 3;
    UCHAR Reserved2 : 1; /* MSb of [12] */
    UCHAR EncryptionParametersKadFormat;
    UINT16 AvailableSupplementalDecryptionKeys; /* Network Byte Order */
    UCHAR Reserved3[8];
#if !defined(__midl)
    UCHAR KADList[0];
#endif
} DATA_ENCRYPTION_STATUS, *PDATA_ENCRYPTION_STATUS;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _DATA_ENCRYPTION_ALGORITHM {
    UCHAR AlgorithmIndex;
    UCHAR Reserved3;
    UINT16 DescriptorLength; /* Network Byte Order */
    UCHAR EncryptCapable : 2; /* LSb of [24] */
    UCHAR DecryptCapable : 2;
    UCHAR DistinguishEncryptedLogicalBlockCapable : 1;
    UCHAR MacKadCapable : 1;
    UCHAR SupplementalDecryptionKeyCapable : 1;
    UCHAR AlgorithmValidForMountedVolume : 1; /* MSb of [24] */
    UCHAR AuthKadFixedLength : 1; /* LSb of [25] */
    UCHAR UnauthKadFixedLength : 1;
    UCHAR VolumeContainsEncryptedLogicalBlocksCapable : 1;
    UCHAR KadFormatCapable : 1;
    UCHAR NonceKadCapable : 2;
    UCHAR AlgorithmValidForCurrentLogicalPosition : 2; /* MSb of [25] */
    UINT16 UnauthKadMaxLength; /* Network Byte Order */
    UINT16 AuthKadMaxLength; /* Network Byte Order */
    UINT16 KeySize; /* Network Byte Order */
    UCHAR EncryptionAlgorithmRecordsEncryptionMode : 1; /* LSb of [32] */
    UCHAR RawDecryptionModeControlCapabilities : 3;
    UCHAR ExternalEncryptionModeControlCapable : 2;
    UCHAR DecryptionKadCapable : 2; /* LSb of [32] */
    UCHAR Reserved4;
    UINT16 MaximumSupplementalDecryptionKeyCount; /* Network Byte Order */
    UCHAR Reserved5[4];
    UINT32 AlgorithmCode; /* Network Byte Order */
} DATA_ENCRYPTION_ALGORITHM, *PDATA_ENCRYPTION_ALGORITHM;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _DATA_ENCRYPTION_CAPABILITIES {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UCHAR ConfigurationPrevented : 2; // LSb of [4]
    UCHAR ExternalDataEncryptionCapable : 2;
    UCHAR Reserved1 : 4; /* MSb of [4] */
    UCHAR Reserved2[15];
#if !defined(__midl)
    DATA_ENCRYPTION_ALGORITHM AlgorithmList[0];
#endif
} DATA_ENCRYPTION_CAPABILITIES, *PDATA_ENCRYPTION_CAPABILITIES;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _DATA_ENCRYPTION_MANAGEMENT_CAPABILITIES {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UCHAR LockCapable : 1; /* LSb of [4] */
    UCHAR Reserved1 : 7; /* MSb of [4] */
    UCHAR ClearKeyOnReservationLossCapable : 1; /* LSb of [5] */
    UCHAR ClearKeyOnReservationPreemptedCapable : 1;
    UCHAR ClearKeyOnDemountCapable : 1;
    UCHAR Reserved2 : 5; /* MSb of [5] */
    UCHAR Reserved3;
    UCHAR PublicScopeCapable : 1; /* LSb of [7] */
    UCHAR LocalScopeCapable : 1;
    UCHAR AITNScopeCapable : 1;
    UCHAR Reserved4 : 5; /* MSb of [7] */
    UCHAR Reserved5[8];
} DATA_ENCRYPTION_MANAGEMENT_CAPABILITIES, *PDATA_ENCRYPTION_MANAGEMENT_CAPABILITIES;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UINT32 PublicKeyType; /* Network Byte Order */
    UINT32 PublicKeyFormat; /* Network Byte Order */
    UINT16 PublicKeyLength; /* Network Byte Order */
#if !defined(__midl)
    UCHAR PublicKey[0];
#endif
} DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY, *PDEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY;
#pragma pack(pop)

typedef struct _RSA2048_PUBLIC_KEY {
    UCHAR Modulus[256];
    UCHAR Exponent[256];
} RSA2048_PUBLIC_KEY, *PRSA2048_PUBLIC_KEY;

#pragma pack(push)
#pragma pack(1)
typedef struct _SUPPORTED_KEY_FORMATS {
    UINT16 PageCode;
    UINT16 PageLength;
#if !defined(__midl)
    UCHAR KeyFormats[0];
#endif
} SUPPORTED_KEY_FORMATS, *PSUPPORTED_KEY_FORMATS;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _NEXT_BLOCK_ENCRYPTION_STATUS {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UINT64 BlockNumber; /* Network Byte Order */
    UCHAR EncryptionStatus : 4; /* LSb of [12] */
    UCHAR CompressionStatus : 4; /* MSb of [12] */
    UCHAR AlgorithmIndex;
    UCHAR RawDecryptionModeDisabledStatus : 1; /* LSb of [14] */
    UCHAR EncryptionModeExternalStatus : 1;
    UCHAR Reserved1 : 6; /* MSb of [14] */
    UCHAR KADFormat;
#if !defined(__midl)
    UCHAR KADList[0];
#endif
} NEXT_BLOCK_ENCRYPTION_STATUS, *PNEXT_BLOCK_ENCRYPTION_STATUS;
#pragma pack(pop)

typedef struct _KEY_HEADER {
    UINT16 PageCode; /* Network Byte Order */
    UINT16 PageLength; /* Network Byte Order */
    UCHAR Lock : 1; /* LSb of [4] */
    UCHAR Reserved1 : 4;
    UCHAR Scope : 3; /* MSb of [4] */
    UCHAR ClearKeyOnReservationLoss : 1; /* LSb of [5] */
    UCHAR ClearKeyOnReservationPreempted : 1;
    UCHAR ClearKeyOnDemount : 1;
    UCHAR SupplementalDecryptionKey : 1;
    UCHAR RawDecryptionModeControl : 2;
    UCHAR CheckExternalEncryptionMode : 2; /* MSb of [5]; */
    UCHAR EncryptionMode;
    UCHAR DecriptionMode;
    UCHAR AlgorithmIndex;
    UCHAR KeyFormat;
    UCHAR KADFormat;
    UCHAR Reserved2[7];
    UINT16 KeyLength;
#if !defined(__midl)
    UCHAR KeyAndKADList[0];
#endif
} KEY_HEADER, *PKEY_HEADER;

typedef struct _PLAIN_KEY_DESCRIPTOR {
    UCHAR Type;
    UCHAR Authenticated : 3; /* LSb of [1] */
    UCHAR Reserved1 : 5; /* MSb of [1] */
    UCHAR Length[2];
#if !defined(__midl)
    UCHAR Descriptor[0];
#endif
} PLAIN_KEY_DESCRIPTOR, *PPLAIN_KEY_DESCRIPTOR;

#pragma pack(push)
#pragma pack(1)
typedef struct _WRAPPED_KEY_DESCRIPTOR {
    UCHAR Type;
    UCHAR Reserved1;
    UINT16 Length; /* Network Byte Order */
#if !defined(__midl)
    UCHAR Descriptor[0];
#endif
} WRAPPED_KEY_DESCRIPTOR, *PWRAPPED_KEY_DESCRIPTOR;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _CERTIFICATE_DATA {
    UCHAR Reserved1[2];
    UINT16 Length; /* Network Byte Order */
#if !defined(__midl)
    UCHAR Certificate[0];
#endif
} CERTIFICATE_DATA, *PCERTIFICATE_DATA;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _SENSE_INFO {
    UCHAR ErrorCode : 7; /* LSb of [0] */
    UCHAR Valid : 1; /* MSb of [0] */
    UCHAR SegmentNumber;
    UCHAR SenseKey : 4; /* LSb of [3] */
    UCHAR Reserved1 : 1;
    UCHAR InvalidLengthIndicator : 1;
    UCHAR EndOfMedium : 1;
    UCHAR Mark : 1; /* MSb of [3] */
    UCHAR InformationBytes[4];
    UCHAR AdditionalSenseLength;
    UCHAR CommandSpecificInformationBytes[4];
    UCHAR AdditionalSenseCode;
    UCHAR AdditionalSenseCodeQualifier;
    UCHAR FieldReplaceableUnitCode;
    UCHAR BitPointer : 3; /* LSb of [15] */
    UCHAR BitPointerValid : 1;
    UCHAR Reserved2 : 2;
    UCHAR CommandData : 1;
    UCHAR SenseKeySpecificValid : 1; /* MSb of [15] */
    UCHAR FieldPointer[2];
    UCHAR Reserved3[3];
    UCHAR Reserved4 : 3; /* LSb of [21] */
    UCHAR CleanNeeded : 1;
    UCHAR Reserved5 : 4; /* MSb of [22] */
    UCHAR Padding[2];
} SENSE_INFO, *PSENSE_INFO;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_ATTRIBUTE_VALUES_SERVICE_ACTION {
    UINT32 AvailableData; /* Network Byte Order */
    UCHAR First;
    UCHAR NumberAvailable;
#if !defined(__midl)
    UCHAR AttributeList[0];
#endif
} MAM_ATTRIBUTE_VALUES_SERVICE_ACTION, *PMAM_ATTRIBUTE_VALUES_SERVICE_ACTION;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_ATTRIBUTE_LIST_SERVICE_ACTION {
    UINT32 AvailableData; /* Network Byte Order */
#if !defined(__midl)
    UINT16 AttributeIdentifierList[0];
#endif
} MAM_ATTRIBUTE_LIST_SERVICE_ACTION, *PMAM_ATTRIBUTE_LIST_SERVICE_ACTION;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_PARTITION_LIST_SERVICE_ACTION {
    UINT16 AvailableData; /* Network Byte Order */
    UCHAR First;
    UCHAR NumberAvailable;
} MAM_PARTITION_LIST_SERVICE_ACTION, *PMAM_PARTITION_LIST_SERVICE_ACTION;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_VOLUME_LIST_SERVICE_ACTION {
    UINT16 AvailableData; /* Network Byte Order */
    UCHAR First;
    UCHAR NumberAvailable;
} MAM_VOLUME_LIST_SERVICE_ACTION, *PMAM_VOLUME_LIST_SERVICE_ACTION;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_SUPPORTED_ATTRIBUTES_SERVICE_ACTION {
    UINT32 AvailableData; /* Network Byte Order */
#if !defined(__midl)
    UINT16 AttributeIdentifierList[0];
#endif
} MAM_SUPPORTED_ATTRIBUTES_SERVICE_ACTION, *PMAM_SUPPORTED_ATTRIBUTES_SERVICE_ACTION;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
typedef struct _MAM_ATTRIBUTE_DATA {
    UINT16 AttributeIdentifier; /* Network Byte Order */
    UCHAR Format : 2; /* MSb of [2] */
    UCHAR Reserved1 : 5;
    UCHAR ReadOnly : 1; /* LSb of [2] */
    UINT16 Length; /* Network Byte Order */
#if !defined(__midl)
    UCHAR Value[0];
#endif
} MAM_ATTRIBUTE_DATA, *PMAM_ATTRIBUTE_DATA;
#pragma pack(pop)

ULONG
CreateSecurityProtocolInSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode);

ULONG
CreateSecurityProtocolOutSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode);

ULONG
CreateReadAttributesSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR serviceAction, UCHAR partitionNumber, UINT16 firstAttributeIdentifier, BOOL useCache);

BOOL
SendSrb(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG length, PULONG returned);

VOID
ParseSimpleSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG status, ULONG length, DWORD returned, PCHAR cdbDescription);

VOID
ParseSecurityCompliance(PSECURITY_PROTOCOL_COMPLIANCE pSecurityCompliance);

PCHAR
NullPaddedNullTerminatedToString(UINT32 arrayLength, PUCHAR characterArray);

VOID
ParseSupportedSecurityProtocolList(PSUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA securityProtocolList, PBOOL pCapTapeEncryption);

VOID
ParseDataEncryptionManagementCapabilities(PDATA_ENCRYPTION_MANAGEMENT_CAPABILITIES encryptionManagementCapabilities);

VOID
ParseDataEncryptionCapabilities(PDATA_ENCRYPTION_CAPABILITIES pBuffer, PDATA_ENCRYPTION_ALGORITHM* ppDataEncryptionAlgorithm, PBOOL configurationPrevented);

BOOL
ParseDeviceServerKeyWrappingPublicKey(PDEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY deviceServerKeyWrappingPublicKey, UINT16 logicalUnitIdentifierLength, PUCHAR logicalUnitIdentifier, PUINT16 wrappedDescriptorsLength, PUCHAR* wrappedDescriptors);

VOID
ParseDeviceIdentifiers(PVPD_IDENTIFICATION_PAGE deviceIdentifiers, PUINT16 pLogicalUnitIdentifierLength, PUCHAR* ppLogicalUnitIdentifier);

VOID
ParseSupportedKeyFormats(PSUPPORTED_KEY_FORMATS supportedKeyFormats, PBOOL pCapRfc3447);

VOID
ParseDataEncryptionStatus(PDATA_ENCRYPTION_STATUS dataEncryptionStatus, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 keyAssociatedDataStatusLength, PCHAR* keyAssociatedDataStatus);

UCHAR
ParseNextBlockEncryptionStatus(PNEXT_BLOCK_ENCRYPTION_STATUS nextBlockStatus, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 keyAssociatedDataNextBlockLength, PCHAR* keyAssociatedDataNextBlock);

BOOL
KeyAuthenticatedDataIsEqual(PUINT16 keyAssociatedDataStatusLength, PCHAR* keyAssociatedDataStatus, PUINT16 keyAssociatedDataNextBlockLength, PCHAR* keyAssociatedDataNextBlock);

VOID
ParseCertificateData(PCERTIFICATE_DATA certificateData);

VOID
SetDataEncryption(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UINT32 allocationLength, UCHAR aesGcmAlgorithmIndex, BOOL clearKey, UCHAR keyFormat, UINT16 keyFieldLength, PUCHAR keyField, int kadFieldLength, PPLAIN_KEY_DESCRIPTOR kad);

BOOL
ProcessKad(BOOL clearKey, UINT16 keyAssociatedDataLength, PUCHAR keyAssociatedData, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 kadFieldLength, PPLAIN_KEY_DESCRIPTOR* ppKadField);

UINT16
ProcessKey(int keyFormat, int keyType, int keyLength, PUCHAR key, UINT16 wrappedDescriptorsLength, PUCHAR wrappedDescriptors, PUCHAR* pKeyField);

UCHAR
GetCdbLength(UCHAR opCode);

ULONG
ResetSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode);

ULONG
ResetSrbOut(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode);

PCHAR
GetSecurityProtocolDescription(UCHAR securityProtocol);

VOID
PrintError(ULONG);

VOID
PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer, _In_ ULONG BufferLength);

VOID
PrintInquiryData(PVOID);

VOID
PrintStatusResultsEx(BOOL, DWORD, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX, ULONG);

VOID
PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX);

BOOL
CheckStatus(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, BOOL status, ULONG length, DWORD returned);

BOOL
WaitForSenseChange(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex);

_Success_(return)
BOOL
QueryPropertyForDevice(_In_ HANDLE, _Out_ PULONG, _Out_ PUCHAR, _Out_ PSTORAGE_BUS_TYPE);

/*
* Command Descriptor Block constants.
*/

#define CDB6GENERIC_LENGTH                   6
#define CDB10GENERIC_LENGTH                  10
#define CDB16GENERIC_LENGTH                  16

#define SETBITON                             1
#define SETBITOFF                            0


/* SPIN / SPOUT Extensions to scsi.h */
#define SECURITY_PROTOCOL_INFO 0x00
#define SECURITY_PROTOCOL_TCG1 0x01
#define SECURITY_PROTOCOL_TCG2 0x02
#define SECURITY_PROTOCOL_TCG3 0x03
#define SECURITY_PROTOCOL_TCG4 0x04
#define SECURITY_PROTOCOL_TCG5 0x05
#define SECURITY_PROTOCOL_TCG6 0x06
#define SECURITY_PROTOCOL_CBCS 0x07
#define SECURITY_PROTOCOL_TAPE 0x20
#define SECURITY_PROTOCOL_ADC3 0x21
#define SECURITY_PROCOCOL_SA_CREATION_CAPABILITIES 0x40
#define SECURITY_PROCOCOL_IKEV2_SCSI 0x41
#define SECURITY_PROCOCOL_UFS 0xEC
#define SECURITY_PROCOCOL_SD_TRUSTEDFLASH 0xED
#define SECURITY_PROCOCOL_ATA_PASSWORD 0xEF

#define SPIN_PROTOCOL_LIST 0x00
#define SPIN_CERTIFICATE_DATA 0x01
#define SPIN_SECURITY_COMPLIANCE 0x02

#define SPIN_SECURITY_COMPLIANCE_FIPS140 0x0001

#define SPIN_SECURITY_COMPLIANCE_FIPS140_2 0x32
#define SPIN_SECURITY_COMPLIANCE_FIPS140_3 0x33

#define SPIN_TAPE_ENCRYPTION_IN_SUPPORT 0x00
#define SPIN_TAPE_ENCRYPTION_OUT_SUPPORT 0x01
#define SPIN_TAPE_ENCRYPTION_CAPABILITIES 0x10
#define SPIN_TAPE_SUPPORTED_KEY_FORMATS 0x11
#define SPIN_TAPE_ENCRYPTION_MANAGEMENT_CAPABILITIES 0x12
#define SPIN_TAPE_ENCRYPTION_STATUS 0x20
#define SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS 0x21
#define SPIN_TAPE_WRAPPED_PUBKEY 0x31

#define SPIN_TAPE_ALGORITHM_AESGCM 0x00010014
#define SPIN_TAPE_KEY_FORMAT_PLAIN 0x00
#define SPIN_TAPE_KEY_FORMAT_WRAPPED 0x02

#define SPIN_TAPE_PUBKEY_TYPE_RSA2048 0x00000000
#define SPIN_TAPE_PUBKEY_TYPE_ECC521 0x00000010

#define SPIN_TAPE_PUBKEY_FORMAT_RSA2048 0x00000000
#define SPIN_TAPE_PUBKEY_FORMAT_ECC521 0x00000000

#define SPIN_TAPE_PUBKEY_LENGTH_AES256 64
#define SPIN_TAPE_PUBKEY_LENGTH_RSA2048 512
#define SPIN_TAPE_PUBKEY_LENGTH_ECC521 133

#define SPOUT_TAPE_SET_DATA_ENCRYPTION 0x0010

#define SPOUT_TAPE_KAD_FORMAT_UNSPEC 0x00
#define SPOUT_TAPE_KAD_FORMAT_BINARY 0x01
#define SPOUT_TAPE_KAD_FORMAT_ASCII 0x02

#define SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH 0x0
#define SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH 0x1
#define SPOUT_TAPE_KAD_PLAIN_TYPE_NONCE 0x2
#define SPOUT_TAPE_KAD_PLAIN_TYPE_METADATA 0x3

#define WRAPPED_KEY_DESCRIPTOR_TYPE_DEVICE_ID 0x00
#define WRAPPED_KEY_DESCRIPTOR_TYPE_WRAPPER_ID 0x01
#define WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_INFO 0x02
#define WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_ID 0x03
#define WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_LENGTH 0x04

/* Read Attribute Extensions to scsi.h */
#define READ_ATTRIBUTE_SERVICE_ATTRIBUTE_VALUES 0x00
#define READ_ATTRIBUTE_SERVICE_ATTRIBUTE_LIST 0x01
#define READ_ATTRIBUTE_SERVICE_VOLUME_LIST 0x02
#define READ_ATTRIBUTE_SERVICE_PARTITION_LIST 0x03
#define READ_ATTRIBUTE_SERVICE_SUPPORTED_ATTRIBUTES 0x05
/* SCSI_ADSENSE_LUN_NOT_READY(0x04) qualifiers */
#define SCSI_SENSEQ_MAM_NOT_ACCESSIBLE 0x10
/* SCSI_ADSENSE_UNRECOVERED_ERROR (0x11) qualifiers */
#define SCSI_SENSEQ_MAM_READ_ERROR 0x12

/* Constants for CM/MAM Attributes */
#define MAM_REMAINING_PARTITION_CAPACITY 0x0000
#define MAM_MAXIMUM_PARTITION_CAPACITY 0x0001
#define MAM_TAPE_ALERT_FLAGS 0x0002
#define MAM_LOAD_COUNT 0x0003
#define MAM_REMAINING_MAM_CAPACITY 0x0004
#define MAM_ASSIGNING_ORG 0x0005
#define MAM_INIT_COUNT 0x0006
#define MAM_VOLUME_ID 0x0008
#define MAM_VOLUME_CHANGE_REF 0x0009
#define MAM_SERIAL_ULTIMATE_LOAD 0x020A
#define MAM_SERIAL_PENULTIMATE_LOAD 0x020B
#define MAM_SERIAL_ANTEPENULTIMATE_LOAD 0x020C
#define MAM_SERIAL_PREANTIPENULTIMATE_LOAD 0x020D
#define MAM_TOTAL_WRITTEN_LIFETIME 0x0220
#define MAM_TOTAL_READ_LIFETIME 0x0221
#define MAM_TOTAL_WRITTEN_ULTIMATE_LOAD 0x0222
#define MAM_TOTAL_READ_ULTIMATE_LOAD 0x0223
#define MAM_FIRST_ENCRYPTED_BLOCK 0x0224
#define MAM_FIRST_UNENCRYPTED_BLOCK 0x0225
#define MAM_MEDIUM_MANUFACTURER 0x0400
#define MAM_MEDIUM_SERIAL 0x0401
#define MAM_MEDIUM_LENGTH 0x0402
#define MAM_MEDIUM_WIDTH 0x0403
#define MAM_MEDIUM_ASSIGNING_ORG 0x0404
#define MAM_MEDIUM_DENSITY_CODE 0x0405
#define MAM_MEDIUM_MANUFACTURE_DATE 0x0406
#define MAM_MAXIMUM_MAM_CAPACITY 0x0407
#define MAM_MEDIUM_TYPE 0x0408
#define MAM_MEDIUM_TYPE_INFO 0x0409
#define MAM_APP_VENDOR 0x0800
#define MAM_APP_NAME 0x0801
#define MAM_APP_VERSION 0x0802
#define MAM_MEDIUM_USER_LABEL 0x0803
#define MAM_LAST_WRITE_TIME 0x0804
#define MAM_TEXT_LOCALE_ID 0x0805
#define MAM_BARCODE 0x0806
#define MAM_HOST_SERVER_NAME 0x0807
#define MAM_MEDIA_POOL 0x0808
#define MAM_PARTITION_USER_LABEL 0x0809
#define MAM_LOAD_UNLOAD_AT_PARTITION 0x080A
#define MAM_APP_FORMAT_VERSION 0x080B
#define MAM_VOLUME_COHERENCY_INFO 0x080C
#define MAM_MEDIUM_GUID 0x0820
#define MAM_MEDIA_POOL_GUID 0x0821
#define MAM_CARTRIDGE_ID 0x1000
#define MAM_CARTRIDGE_ID_ALT 0x1001
#define MAM_VOLUME_LOCKED 0x1623

#define MAM_LOCALE_ASCII 0x00
#define MAM_LOCALE_LATIN_1 0x01
#define MAM_LOCALE_LATIN_2 0x02
#define MAM_LOCALE_LATIN_3 0x03
#define MAM_LOCALE_LATIN_4 0x04
#define MAM_LOCALE_LATIN_CYRILLIC 0x05
#define MAM_LOCALE_LATIN_ARABIC 0x06
#define MAM_LOCALE_LATIN_GREEK 0x07
#define MAM_LOCALE_LATIN_HEBREW 0x08
#define MAM_LOCALE_LATIN_5 0x09
#define MAM_LOCALE_LATIN_6 0x0A
#define MAM_LOCALE_UNICODE 0x80
#define MAM_LOCALE_UTF8 0x81
