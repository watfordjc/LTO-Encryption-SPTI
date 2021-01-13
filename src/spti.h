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

#pragma warning(disable:4200) // array[0] is not a warning for this file
#pragma warning(disable:4214) // nonstandard extension used : bit field types other than int

#define SPT_CDB_LENGTH 32
#define SPT_SENSE_LENGTH 32
#define SPTWB_DATA_LENGTH 4096

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS {
    SCSI_PASS_THROUGH spt;
    ULONG             Filler;      // realign buffers to double word boundary
    UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
    UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];
    } SCSI_PASS_THROUGH_WITH_BUFFERS, *PSCSI_PASS_THROUGH_WITH_BUFFERS;
    
typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS_EX {
    SCSI_PASS_THROUGH_EX spt;
    UCHAR             ucCdbBuf[SPT_CDB_LENGTH-1];       // cushion for spt.Cdb
    ULONG             Filler;      // realign buffers to double word boundary
    STOR_ADDR_BTL8    StorAddress;
    UCHAR             ucSenseBuf[SPT_SENSE_LENGTH];
    UCHAR             ucDataBuf[SPTWB_DATA_LENGTH];     // buffer for DataIn or DataOut
} SCSI_PASS_THROUGH_WITH_BUFFERS_EX, *PSCSI_PASS_THROUGH_WITH_BUFFERS_EX;

#pragma pack(push)
#pragma pack(1)
typedef struct _DATA_ENCRYPTION_CAPABILITIES {
    UINT16 PageCode; // Network Byte Order
    UINT16 PageLength; // Network Byte Order
    UCHAR ConfigurationPrevented : 2;
    UCHAR ExternalDataEncryptionCapable : 2;
    UCHAR Reserved1 : 4;
    UCHAR Reserved2[15];
    UCHAR AlgorithmIndex;
    UCHAR Reserved3;
    UINT16 DescriptorLength; // Network Byte Order
    UCHAR EncryptCapable : 2;
    UCHAR DecryptCapable : 2;
    UCHAR DistinguishEncryptedLogicalBlockCapable : 1;
    UCHAR MacKadCapable : 1;
    UCHAR SupplementalDecryptionKeyCapable : 1;
    UCHAR AlgorithmValidForMountedVolume : 1;
    UCHAR AuthKadFixedLength : 1;
    UCHAR UnauthKadFixedLength : 1;
    UCHAR VolumeContainsEncryptedLogicalBlocksCapable : 1;
    UCHAR KadFormatCapable : 1;
    UCHAR NonceKadCapable : 2;
    UCHAR AlgorithmValidForCurrentLogicalPosition : 2;
    UINT16 UnauthKadMaxLength; // Network Byte Order
    UINT16 AuthKadMaxLength; // Network Byte Order
    UINT16 KeySize; // Network Byte Order
    UCHAR EncryptionAlgorithmRecordsEncryptionMode : 1;
    UCHAR RawDecryptionModeControlCapabilities : 3;
    UCHAR ExternalEncryptionModeControlCapable : 2;
    UCHAR DecryptionKadCapable : 2;
    UCHAR Reserved4;
    UINT16 MaximumSupplementalDecryptionKeyCount; // Network Byte Order
    UCHAR Reserved5[4];
    UINT32 AlgorithmCode; // Network Byte Order
} DATA_ENCRYPTION_CAPABILITIES, *PDATA_ENCRYPTION_CAPABILITIES;
#pragma pack(pop)

typedef struct _KEY_HEADER {
    UCHAR PageCode[2];
    UCHAR PageLength[2];
    UCHAR Lock : 1; // LSb of [4]
    UCHAR Reserved1 : 4;
    UCHAR Scope : 3; // MSb of [4]
    UCHAR CKORL : 1; // LSb of [5]
    UCHAR CKORP : 1;
    UCHAR CKOD : 1;
    UCHAR SDK : 1;
    UCHAR RDMC : 2;
    UCHAR CEEM : 2; // MSb of [5];
    UCHAR EncryptionMode;
    UCHAR DecriptionMode;
    UCHAR AlgorithmIndex;
    UCHAR KeyFormat;
    UCHAR KADFormat;
    UCHAR Reserved2[7];
} KEY_HEADER, *PKEY_HEADER;

typedef struct _PLAIN_KEY {
    UCHAR PageCode[2];
    UCHAR PageLength[2];
    UCHAR Lock : 1; // LSb of [4]
    UCHAR Reserved1 : 4;
    UCHAR Scope : 3; // MSb of [4]
    UCHAR CKORL : 1; // LSb of [5]
    UCHAR CKORP : 1;
    UCHAR CKOD : 1;
    UCHAR SDK : 1;
    UCHAR RDMC : 2;
    UCHAR CEEM : 2; // MSb of [5];
    UCHAR EncryptionMode;
    UCHAR DecriptionMode;
    UCHAR AlgorithmIndex;
    UCHAR KeyFormat;
    UCHAR KADFormat;
    UCHAR Reserved2[7];
    UCHAR KeyLength[2];
    UCHAR Key[32];
#if !defined(__midl)
    UCHAR KADList[0];
#endif
} PLAIN_KEY, *PPLAIN_KEY;

typedef struct _PLAIN_KEY_DESCRIPTOR {
    UCHAR Type;
    UCHAR Authenticated : 3; // LSb of [1]
    UCHAR Reserved1 : 5; // MSb of [1]
    UCHAR Length[2];
#if !defined(__midl)
    UCHAR Descriptor[0];
#endif
} PLAIN_KEY_DESCRIPTOR, *PPLAIN_KEY_DESCRIPTOR;

ULONG
CreateSecurityProtocolInSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode);

BOOL
SendSrb(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG length, PULONG returned);

VOID
ParseSimpleSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG status, ULONG length, DWORD returned, PCHAR cdbDescription);

UCHAR
GetCdbLength(UCHAR groupCode);

ULONG
ResetSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode);

ULONG
ResetSrbOut(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, int cdbLength);

PCHAR
GetSecurityProtocolDescription(UCHAR securityProtocol);

VOID
PrintError(ULONG);

VOID
PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer, _In_ ULONG BufferLength);

VOID
PrintInquiryData(PVOID);

VOID
PrintStatusResults(BOOL, DWORD, PSCSI_PASS_THROUGH_WITH_BUFFERS, ULONG);

VOID
PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS);

VOID
PrintStatusResultsEx(BOOL, DWORD, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX, ULONG);

VOID
PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX);

_Success_(return)
BOOL
QueryPropertyForDevice(_In_ HANDLE, _Out_ PULONG, _Out_ PUCHAR, _Out_ PSTORAGE_BUS_TYPE);


//
// Command Descriptor Block constants.
//

#define CDB6GENERIC_LENGTH                   6
#define CDB10GENERIC_LENGTH                  10

#define SETBITON                             1
#define SETBITOFF                            0


// SPIN/SPOUT Extensions to scsi.h
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

#define SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH 0X0
#define SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH 0X1
#define SPOUT_TAPE_KAD_PLAIN_TYPE_NONCE 0X2
#define SPOUT_TAPE_KAD_PLAIN_TYPE_METADATA 0X3