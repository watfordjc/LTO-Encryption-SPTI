/*++

Copyright (c) 1992  Microsoft Corporation

Module Name:

	spti.c

Abstract:

	Win32 application that can communicate directly with SCSI devices via
	IOCTLs.

Author:


Environment:

	User mode.

Notes:


Revision History:

--*/

#include <windows.h>
#include <devioctl.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <strsafe.h>
#include <intsafe.h>
#define _NTSCSI_USER_MODE_
#include <scsi.h>
#include "spti.h"

#define NAME_COUNT  25

#define BOOLEAN_TO_STRING(_b_) \
( (_b_) ? "True" : "False" )

#if defined(_X86_)
#define PAGE_SIZE  0x1000
#define PAGE_SHIFT 12L
#elif defined(_AMD64_)
#define PAGE_SIZE  0x1000
#define PAGE_SHIFT 12L
#elif defined(_IA64_)
#define PAGE_SIZE 0x2000
#define PAGE_SHIFT 13L
#else
// undefined platform?
#define PAGE_SIZE  0x1000
#define PAGE_SHIFT 12L
#endif


LPCSTR BusTypeStrings[] = {
	"Unknown",
	"SCSI",
	"ATAPI",
	"ATA",
	"IEEE 1394",
	"SSA",
	"Fibre Channel",
	"USB",
	"RAID",
	"iSCSI",
	"Serial Attached SCSI (SAS)",
	"SATA",
	"Secure Digital (SD)",
	"MultiMedia Card (MMC)",
	"Virtual",
	"FileBackedVirtual",
	"Spaces",
	"NVMe",
	"Scm",
	"Ufs",
	"Not Defined",
};
#define NUMBER_OF_BUS_TYPE_STRINGS (sizeof(BusTypeStrings)/sizeof(BusTypeStrings[0]))

LPCSTR DeviceIdentifiers[] = {
	"Logical Unit Identifier",
	"Port Name",
	"Port Identifier",
	"Target Port Group Identifier",
	"Target Name (code set 1)",
	"Target Name (code set 2)",
	"Not Defined"
};
#define NUMBER_OF_DEVICE_IDENTIFIERS (sizeof(DeviceIdentifiers)/sizeof(DeviceIdentifiers[0]))

VOID
__cdecl
main(
	_In_ int argc,
	_In_z_ char* argv[]
)

{
	BOOL status = 0;
	DWORD accessMode = 0, shareMode = 0;
	HANDLE fileHandle = NULL;
	ULONG alignmentMask = 0; // default == no alignment requirement
	UCHAR srbType = SRB_TYPE_SCSI_REQUEST_BLOCK; // default == SRB_TYPE_SCSI_REQUEST_BLOCK
	STORAGE_BUS_TYPE storageBusType = BusTypeUnknown;
	PUCHAR pUnAlignedBuffer = NULL;
	SCSI_PASS_THROUGH_WITH_BUFFERS_EX sptwb_ex;
	CHAR string[NAME_COUNT];

	ULONG length = 0,
		errorCode = 0,
		returned = 0;

	if ((argc < 2) || (argc > 3)) {
		printf("Usage:  %s <port-name> [mode] [key]\n", argv[0]);
		printf("Examples:\n");
		printf("    spti Tape0         (open the tape class driver in SHARED READ mode)\n");
		printf("    spti Tape0 D00D00  (Use RFC 3447 wrapped key 0xD00D00 on drive Tape0)\n");
		printf("    spti Tape0 weak    (Use a hardcoded really weak test key on drive Tape0)\n");
		printf("    spti Tape0 none    (Disable encryption and decryption on drive Tape0)\n");
		return;
	}

	StringCbPrintf(string, sizeof(string), "\\\\.\\%s", argv[1]);

	shareMode = FILE_SHARE_READ;
	accessMode = GENERIC_WRITE | GENERIC_READ;
	int logicalUnitIdentifierLength = 0;
	UCHAR* logicalUnitIdentifier = NULL;
	BOOL capRfc3447 = FALSE;
	CHAR aesGcmAlgorithmIndex = -1;
	int wrappedDescriptorsLength = 0;
	UCHAR* wrappedDescripters = NULL;
	int keyType = -1;
	int keyFormat = -1;
	int keyLength = 0;
	UCHAR* key = NULL;
	BOOL testKey = FALSE;
	BOOL noKey = FALSE;

	if (argc == 3) {
		if (strcmp(argv[2], "weak") == 0) {
			testKey = TRUE;
		}
		else if (strcmp(argv[2], "none") == 0) {
			noKey = TRUE;
		}
		else {
			key = (UCHAR*)argv[2];
			keyLength = (int)strlen(argv[2]);
			switch (keyLength)
			{
			case SPIN_TAPE_PUBKEY_LENGTH_RSA2048:
				keyType = SPIN_TAPE_PUBKEY_TYPE_RSA2048;
				keyFormat = SPIN_TAPE_KEY_FORMAT_WRAPPED;
				break;
			case SPIN_TAPE_PUBKEY_LENGTH_ECC521:
				keyType = SPIN_TAPE_PUBKEY_TYPE_ECC521;
				keyFormat = SPIN_TAPE_KEY_FORMAT_WRAPPED;
				break;
			case SPIN_TAPE_PUBKEY_LENGTH_AES256:
				keyFormat = SPIN_TAPE_KEY_FORMAT_PLAIN;
				break;
			}
		}
	}

	fileHandle = CreateFile(string,
		accessMode,
		shareMode,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		errorCode = GetLastError();
		printf("Error opening %s. Error: %d\n",
			string, errorCode);
		PrintError(errorCode);
		return;
	}

	//
	// Get the alignment requirements
	//

	status = QueryPropertyForDevice(fileHandle, &alignmentMask, &srbType, &storageBusType);
	if (!status) {
		errorCode = GetLastError();
		printf("Error getting device and/or adapter properties; "
			"error was %d\n", errorCode);
		PrintError(errorCode);
		CloseHandle(fileHandle);
		return;
	}

	printf("Alignment mask: 0x%08x\n\n", alignmentMask);

	printf("Using %s%s.\n\n", BusTypeStrings[storageBusType], storageBusType == BusTypeSas ? "" : " - only tested with SAS");

	//
	// Send SCSI Pass Through
	//

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		UCHAR cdbLength = GetCdbLength(SCSIOP_SECURITY_PROTOCOL_IN);
		if (cdbLength == 0) {
			CloseHandle(fileHandle);
			return;
		}
		length = ResetSrbIn(&sptwb_ex, cdbLength);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_INFO;
		sptwb_ex.spt.Cdb[3] = SPIN_SECURITY_COMPLIANCE;
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		printf("Parsing Security Compliance page...\n");
		int pageLength = (sptwb_ex.ucDataBuf[0] << 24) & 0xFF000000 | (sptwb_ex.ucDataBuf[1] << 16) & 0xFF0000 | (sptwb_ex.ucDataBuf[2] << 8) & 0xFF00 | sptwb_ex.ucDataBuf[3] & 0xFF;
		int currentDescriptorLength = 0;
		for (int i = 0; i < pageLength; i += currentDescriptorLength)
		{
			int descriptorType = (sptwb_ex.ucDataBuf[4 + i + 0] << 8) & 0xFF00 | sptwb_ex.ucDataBuf[4 + i + 1] & 0xFF;
			char* description;
			switch (descriptorType)
			{
			case 0x0001:
				description = "Security requirements for cryptographic modules";
				break;
			default:
				description = "Unknown";
				break;
			}
			printf("Descriptor Type: 0x%04x (%s)\n", descriptorType, description);
			currentDescriptorLength = (sptwb_ex.ucDataBuf[4 + i + 4] << 24) & 0xFF000000 | (sptwb_ex.ucDataBuf[4 + i + 5] << 16) & 0xFF0000 | (sptwb_ex.ucDataBuf[4 + i + 6] << 8) & 0xFF00 | sptwb_ex.ucDataBuf[4 + i + 7] & 0xFF;
			if (descriptorType == 0x0001) {
				UCHAR fipsRevision = sptwb_ex.ucDataBuf[4 + i + 8];
				switch (fipsRevision) {
				case 0x32:
					description = "FIPS 140-2";
					break;
				case 0x33:
					description = "FIPS 140-3";
					break;
				default:
					description = "Unknown";
				}
				printf("Revision: %s\n", description);
				printf("Overall Security Level: %c\n", sptwb_ex.ucDataBuf[4 + i + 9]);
				printf("Hardware Level: ");
				char currentChar;
				BOOL endOfLeadingZeroes = FALSE;
				for (int j = 0; j < 128; j++)
				{
					currentChar = sptwb_ex.ucDataBuf[4 + i + 10 + j];
					if (currentChar == 0 && !endOfLeadingZeroes) {
						continue;
					}
					else if (currentChar == 0 && endOfLeadingZeroes) {
						break;
					}
					else if (currentChar != 0) {
						printf("%c", currentChar);
						if (!endOfLeadingZeroes) {
							endOfLeadingZeroes = TRUE;
						}
					}
				}
				printf("\n");
				printf("Software Level: ");
				endOfLeadingZeroes = FALSE;
				for (int j = 0; j < 128; j++)
				{
					currentChar = sptwb_ex.ucDataBuf[4 + i + 138 + j];
					if (currentChar == 0 && !endOfLeadingZeroes) {
						continue;
					}
					else if (currentChar == 0 && endOfLeadingZeroes) {
						break;
					}
					else if (currentChar != 0) {
						printf("%c", currentChar);
						if (!endOfLeadingZeroes) {
							endOfLeadingZeroes = TRUE;
						}
					}
				}
				printf("\n");
			}
			i += 8;
		}
		printf("\n");

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
	}


	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		printf("Using STORAGE_REQUEST_BLOCK.\n\n");
		length = ResetSrbIn(&sptwb_ex, CDB12GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_INFO; // information
		sptwb_ex.spt.Cdb[2] = SPIN_PROTOCOL_LIST; // supported protocol list
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		//PrintStatusResultsEx(status, returned, &sptwb_ex, length);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
		else
		{
			PSUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA data = (void*)sptwb_ex.ucDataBuf;
			BOOL capTapeEncryption = FALSE;
			int listCount = data->SupportedSecurityListLength[0] << 8 | data->SupportedSecurityListLength[1];
			for (int i = 0; i < listCount; i++)
			{
				char* securityProtocol = "";
				switch (data->SupportedSecurityProtocol[i])
				{
				case SECURITY_PROTOCOL_INFO:
					securityProtocol = "Security protocol information";
					break;
				case SECURITY_PROTOCOL_TCG1:
				case SECURITY_PROTOCOL_TCG2:
				case SECURITY_PROTOCOL_TCG3:
				case SECURITY_PROTOCOL_TCG4:
				case SECURITY_PROTOCOL_TCG5:
				case SECURITY_PROTOCOL_TCG6:
					securityProtocol = "TCG";
					break;
				case SECURITY_PROTOCOL_TAPE:
					securityProtocol = "Tape Data Encryption (SSC-3)";
					capTapeEncryption = TRUE;
					break;
				case SECURITY_PROTOCOL_ADC3:
					securityProtocol = "Data Encryption Configuration (ADC-3)";
					break;
				case SECURITY_PROCOCOL_SA_CREATION_CAPABILITIES:
					securityProtocol = "SA Creation Capabilities (SPC-5)";
					break;
				case SECURITY_PROCOCOL_IKEV2_SCSI:
					securityProtocol = "IKEv2-SCSI (SPC-5)";
					break;
				case SECURITY_PROCOCOL_UFS:
					securityProtocol = "JEDEC Universal Flash Storage (UFS)";
					break;
				case SECURITY_PROCOCOL_SD_TRUSTEDFLASH:
					securityProtocol = "SDcard TrustedFlash Security Systems Specification 1.1.3";
					break;
				case SECURITY_PROTOCOL_IEEE1667:
					securityProtocol = "IEEE 1667";
					break;
				case SECURITY_PROCOCOL_ATA_PASSWORD:
					securityProtocol = "ATA Device Server Password Security (SAT-3)";
					break;
				default:
					securityProtocol = "Unknown";
					break;
				}
				printf("Supported Security Protocol: 0x%02X (%s)\n", data->SupportedSecurityProtocol[i], securityProtocol);
			}
			printf("\n");
			if (capTapeEncryption)
			{
				printf("This device supports Tape Data Encryption.\n\n");
			}
			else
			{
				fprintf(stderr, "This device doesn't support Tape Data Encryption.\n");
				CloseHandle(fileHandle);
				return;
			}
		}

		//PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
	}
	else
	{
		printf("Using SCSI_REQUEST_BLOCK - only tested with STORAGE_REQUEST_BLOCK.\n\n\n");
	}

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		length = ResetSrbIn(&sptwb_ex, CDB12GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_TAPE; // tape encryption
		sptwb_ex.spt.Cdb[3] = SPIN_TAPE_ENCRYPTION_CAPABILITIES; // data encryption capabilities
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
		int pageCode = sptwb_ex.ucDataBuf[0] << 8 | sptwb_ex.ucDataBuf[1];
		if (pageCode == SPIN_TAPE_ENCRYPTION_CAPABILITIES)
		{
			char* description;
			printf("Parsing Data Encryption Capabilities page...\n");
			int pageLength = sptwb_ex.ucDataBuf[2] << 8 | sptwb_ex.ucDataBuf[3];
			printf("Page length: %d bytes\n", pageLength);
			int capExtdecc = sptwb_ex.ucDataBuf[4] & 0b00001100;
			printf("External Data Encryption Capable (EXTDECC): %s\n", capExtdecc ? "True" : "False");
			int capCfgP = sptwb_ex.ucDataBuf[4] & 0b00000011;
			switch (capCfgP)
			{
			case 0b01:
				description = "False";
				break;
			case 0b10:
				description = "True";
				break;
			default:
				description = "Unknown";
				break;
			}
			printf("Configuration Prevented (CFG_P): %s\n", description);
			UCHAR algorithmIndex = sptwb_ex.ucDataBuf[20];
			printf("Algorithm index: 0x%02X\n", algorithmIndex);
			int descriptorLength = sptwb_ex.ucDataBuf[22] << 8 | sptwb_ex.ucDataBuf[23];
			printf("Descriptor Length: %d bytes\n", descriptorLength);
			printf("Algorithm Valid For Mounted Volume (AVFMV): %s\n", ((sptwb_ex.ucDataBuf[24] & 0b10000000) >> 7) == 0b1 ? "True" : "False");
			printf("Supplemental Decryption Key Capable (SDK_C): %s\n", ((sptwb_ex.ucDataBuf[24] & 0b01000000) >> 6) == 0b1 ? "True" : "False");
			printf("Message Authentication Code Capable (MAC_C): %s\n", ((sptwb_ex.ucDataBuf[24] & 0b00100000) >> 5) == 0b1 ? "True" : "False");
			printf("Distinguish Encrypted Logical Block Capable (DELB_C): %s\n", ((sptwb_ex.ucDataBuf[24] & 0b00010000) >> 4) == 0b1 ? "True" : "False");
			int capDecrypt = (sptwb_ex.ucDataBuf[24] & 0b00001100) >> 2;
			switch (capDecrypt)
			{
			case 0b00:
				description = "No Capability";
				break;
			case 0b01:
				description = "Software";
				break;
			case 0b10:
				description = "Hardware";
				break;
			case 0b11:
				description = "Capable with External Control";
				break;
			}
			printf("Decryption Capable (Decrypt_C): %s\n", description);
			int capEncrypt = sptwb_ex.ucDataBuf[24] & 0b00000011;
			switch (capEncrypt)
			{
			case 0b00:
				description = "No Capability";
				break;
			case 0b01:
				description = "Software";
				break;
			case 0b10:
				description = "Hardware";
				break;
			case 0b11:
				description = "Capable with External Control";
				break;
			}
			printf("Encryption Capable (Encrypt_C): %s\n", description);
			int capAvfclp = (sptwb_ex.ucDataBuf[25] & 0b11000000) >> 6;
			switch (capAvfclp)
			{
			case 0b00:
				description = "Not applicable or no tape loaded";
				break;
			case 0b01:
				description = "Not valid at current logical position";
				break;
			case 0b10:
				description = "Valid at current logical position";
				break;
			default:
				description = "Unknown";
				break;
			}
			printf("Algorithm Valid For Current Logical Position (AVFCLP): %s\n", description);
			printf("Nonce value descriptor capable (NONCE_C): %s\n", (sptwb_ex.ucDataBuf[25] & 0b00110000) >> 4 == 0b11 ? "True" : "False");
			printf("KAD Format Capable (KADF_C): %s\n", (sptwb_ex.ucDataBuf[25] & 0b00001000) >> 3 == 0b1 ? "True" : "False");
			printf("Volume Contains Encrypted Logical Blocks Capable (VCELB_C): %s\n", (sptwb_ex.ucDataBuf[25] & 0b00000100) >> 2 == 0b1 ? "True" : "False");
			printf("Unauthenticated KAD Fixed Length (UKADF): %s\n", (sptwb_ex.ucDataBuf[25] & 0b00000010) >> 1 == 0b1 ? "Max UKAD Bytes" : "1 Byte to Max UKAD Bytes");
			printf("Authenticated KAD Fixed Length (AKADF): %s\n", (sptwb_ex.ucDataBuf[25] & 0b00000001) == 0b1 ? "Max AKAD Bytes" : "1 Byte to Max AKAD Bytes");
			int maxUnauthKeyBytes = sptwb_ex.ucDataBuf[26] << 8 | sptwb_ex.ucDataBuf[27];
			printf("Maximum Unauthenticated Key-Associated Data Bytes: %d\n", maxUnauthKeyBytes);
			int maxAuthKeyBytes = sptwb_ex.ucDataBuf[28] << 8 | sptwb_ex.ucDataBuf[29];
			printf("Maximum Authenticated Key-Associated Data Bytes: %d\n", maxAuthKeyBytes);
			int keySize = sptwb_ex.ucDataBuf[30] << 8 | sptwb_ex.ucDataBuf[31];
			printf("Key Size: %d bytes (%d-bit)\n", keySize, keySize * 8);
			int capDkad = (sptwb_ex.ucDataBuf[32] & 0b11000000) >> 6;
			switch (capDkad)
			{
			case 0b00:
				description = "Unspecified";
				break;
			case 0b01:
				description = "Required";
				break;
			case 0b10:
				description = "Not Allowed";
				break;
			case 0b11:
				description = "Capable";
				break;
			}
			printf("Decryption KAD Capability: %s\n", description);
			int capEemc = (sptwb_ex.ucDataBuf[32] & 0b00110000) >> 4;
			switch (capEemc)
			{
			case 0b00:
			case 0b11:
				description = "Unspecified";
				break;
			case 0b01:
				description = "False";
				break;
			case 0b10:
				description = "True";
				break;
			}
			printf("External Encryption Mode Control Capable (EEMC_C): %s\n", description);
			int capRdmc = (sptwb_ex.ucDataBuf[32] & 0b00001110) >> 1;
			if (capRdmc == 0x4)
			{
				printf("Raw Decryption Mode Control (RDMC_C): Raw decryption not allowed by default\n");
			}
			else
			{
				printf("Raw Decryption Mode Control (RDMC_C): 0x%02X\n", capRdmc);
			}
			int capEarem = sptwb_ex.ucDataBuf[32] & 0b1;
			printf("Encryption Algorithm Records Encryption Mode (EAREM): %s\n", capEarem == 1 ? "True" : "False");
			int maxSupplementalKeyCount = sptwb_ex.ucDataBuf[34] << 8 | sptwb_ex.ucDataBuf[35];
			printf("Maximum number of supplemental decryption keys: %d\n", maxSupplementalKeyCount);
			long algorithmCode = sptwb_ex.ucDataBuf[40] << 24 | sptwb_ex.ucDataBuf[41] << 16 | sptwb_ex.ucDataBuf[42] << 8 | sptwb_ex.ucDataBuf[43];
			if (algorithmCode == SPIN_TAPE_ALGORITHM_AESGCM)
			{
				printf("Algorithm: AES-GCM (AES%d-GCM)\n", keySize * 8);
				aesGcmAlgorithmIndex = algorithmIndex;
			}
			else
			{
				printf("Unknown Algorithm: 0x%08X\n", algorithmCode);
			}

			printf("\n\n");
		}

		//  PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
	}

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		length = ResetSrbIn(&sptwb_ex, CDB6GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_INQUIRY;
		sptwb_ex.spt.Cdb[1] = CDB_INQUIRY_EVPD;
		sptwb_ex.spt.Cdb[2] = VPD_DEVICE_IDENTIFIERS;
		sptwb_ex.spt.Cdb[3] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[4] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
		int pageCode = sptwb_ex.ucDataBuf[1];
		if (pageCode == VPD_DEVICE_IDENTIFIERS) {

			printf("Parsing Device Identifiers page...\n");
			printf("Peripheral Qualifier: 0x%01X\n", (sptwb_ex.ucDataBuf[0] & 0b11100000) >> 5);
			printf("Peripheral Device Type: 0x%02X\n", sptwb_ex.ucDataBuf[0] & 0x1F);
			int pageLength = sptwb_ex.ucDataBuf[3];
			printf("Page Length: %d bytes (0x%02X)\n\n", pageLength, pageLength);
			int identifierTotalLength = 0;
			int currentIdentifier = 0;
			for (int i = 4; i < pageLength; i += identifierTotalLength)
			{
				//printf("Protocol identifier: 0x%01X\n", (sptwb_ex.ucDataBuf[i] & 0xF0) >> 8);
				//printf("Code Set: 0x%01X\n", sptwb_ex.ucDataBuf[i] & 0xF);
				//printf("PIV: 0x%01X\n", (sptwb_ex.ucDataBuf[i + 1] & 0b10000000) >> 7);
				//printf("Rsvd: 0x%01X\n", (sptwb_ex.ucDataBuf[i + 1] & 0b01000000) >> 6);
				//printf("Association: 0x%01X\n", (sptwb_ex.ucDataBuf[i + 1] & 0b00110000) >> 4);
				printf("Identifier Type: 0x%01X\n", sptwb_ex.ucDataBuf[i + 1] & 0xF);
				printf("Device Identifier (%s):\n", currentIdentifier < NUMBER_OF_DEVICE_IDENTIFIERS ? DeviceIdentifiers[currentIdentifier] : DeviceIdentifiers[NUMBER_OF_DEVICE_IDENTIFIERS - 1]);
				int identifierLength = sptwb_ex.ucDataBuf[i + 3];
				if (currentIdentifier == 0) {
					logicalUnitIdentifierLength = identifierLength;
					logicalUnitIdentifier = calloc(sizeof(UCHAR), identifierLength);
					memcpy(logicalUnitIdentifier, sptwb_ex.ucDataBuf + i + 4, identifierLength);
				}
				identifierTotalLength = 4 + identifierLength;
				PrintDataBuffer(sptwb_ex.ucDataBuf + i + 4, identifierLength);
				currentIdentifier++;
			}
		}

	}

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		length = ResetSrbIn(&sptwb_ex, CDB12GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_TAPE; // tape encryption
		sptwb_ex.spt.Cdb[3] = SPIN_TAPE_SUPPORTED_KEY_FORMATS; // supported key formats page
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
		int pageCode = sptwb_ex.ucDataBuf[0] << 8 | sptwb_ex.ucDataBuf[1];
		if (pageCode == SPIN_TAPE_SUPPORTED_KEY_FORMATS)
		{
			char* description;
			printf("Parsing Supported Key Formats page...\n");
			int pageLength = sptwb_ex.ucDataBuf[2] << 8 | sptwb_ex.ucDataBuf[3];
			printf("Page length: %d bytes\n\n", pageLength);

			for (int i = 0; i < pageLength; i++)
			{
				switch (sptwb_ex.ucDataBuf[4 + i])
				{
				case SPIN_TAPE_KEY_FORMAT_PLAIN:
					description = "Plain-text";
					break;
				case SPIN_TAPE_KEY_FORMAT_WRAPPED:
					description = "Wrapped/RFC 3447";
					capRfc3447 = TRUE;
					break;
				default:
					description = "Unknown";
					break;
				}

				printf("Supported Key Format: 0x%02X (%s)\n", sptwb_ex.ucDataBuf[4 + i], description);
			}

			printf("\n\n");
		}

		//  PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
	}

	fprintf(
		capRfc3447 ? stdout : stderr,
		"This device %s RFC 3447 AES Key-Wrapping.\n\n", capRfc3447 ? "supports" : "doesn't support"
	);

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		length = ResetSrbIn(&sptwb_ex, CDB12GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_TAPE; // tape encryption
		sptwb_ex.spt.Cdb[3] = SPIN_TAPE_ENCRYPTION_STATUS; // supported key formats page
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}

		//PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
	}

	// If the device supports AES key wrapping (RFC 3447), try to obtain the public key
	if (capRfc3447 && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		length = ResetSrbIn(&sptwb_ex, CDB12GENERIC_LENGTH);
		sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
		sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_TAPE; // tape encryption
		sptwb_ex.spt.Cdb[3] = SPIN_TAPE_WRAPPED_PUBKEY; // device server key wrapping public key page
		sptwb_ex.spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		sptwb_ex.spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		sptwb_ex.spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		sptwb_ex.spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X\n\n", sptwb_ex.spt.ScsiStatus);
			PrintStatusResultsEx(status, returned, &sptwb_ex, length);
		}
		int pageCode = sptwb_ex.ucDataBuf[0] << 8 | sptwb_ex.ucDataBuf[1];
		if (pageCode == SPIN_TAPE_WRAPPED_PUBKEY)
		{
			printf("Parsing Device Server Key Wrapping Public Key page...\n");
			int pageLength = sptwb_ex.ucDataBuf[2] << 8 | sptwb_ex.ucDataBuf[3];
			printf("Page length: %d bytes\n\n", pageLength);
			long publicKeyType = sptwb_ex.ucDataBuf[4] << 24 | sptwb_ex.ucDataBuf[5] << 16 | sptwb_ex.ucDataBuf[6] << 8 | sptwb_ex.ucDataBuf[7];
			long publicKeyFormat = sptwb_ex.ucDataBuf[8] << 24 | sptwb_ex.ucDataBuf[9] << 16 | sptwb_ex.ucDataBuf[10] << 8 | sptwb_ex.ucDataBuf[11];
			int publicKeyLength = sptwb_ex.ucDataBuf[12] << 8 | sptwb_ex.ucDataBuf[13];
			int modulusLength = 0;
			int exponentLength = 0;
			char* description;
			BOOL keyValueConsistent = FALSE;
			BOOL keyLengthConsistent = FALSE;
			switch (publicKeyType) {
			case SPIN_TAPE_PUBKEY_TYPE_RSA2048:
				description = "RSA-2048";
				keyValueConsistent = publicKeyFormat == SPIN_TAPE_PUBKEY_FORMAT_RSA2048;
				keyLengthConsistent = publicKeyLength == SPIN_TAPE_PUBKEY_LENGTH_RSA2048;
				modulusLength = SPIN_TAPE_PUBKEY_LENGTH_RSA2048 / 2; // 256 bytes for RSA-2048
				exponentLength = SPIN_TAPE_PUBKEY_LENGTH_RSA2048 / 2; // 256 bytes for RSA-2048
				break;
			case SPIN_TAPE_PUBKEY_TYPE_ECC521:
				description = "ECC-521";
				keyValueConsistent = publicKeyFormat == SPIN_TAPE_PUBKEY_FORMAT_ECC521;
				keyLengthConsistent = publicKeyLength == SPIN_TAPE_PUBKEY_LENGTH_ECC521;
				// TODO: Work out how X9.63 stores ECC keys and how to calculate length parameters
				break;
			default:
				description = "Unknown";
				break;
			}
			if (!keyValueConsistent)
			{
				fprintf(stderr, "Public Key type %s and key format 0x%08x are not consistent.\n", description, publicKeyFormat);
				CloseHandle(fileHandle);
				return;
			}
			if (!keyLengthConsistent)
			{
				fprintf(stderr, "Public Key type %s and wrapped key length (%d bytes) are not consistent.\n", description, publicKeyLength);
				CloseHandle(fileHandle);
				return;
			}
			printf("Public Key Type: %s\n", description);
			UCHAR* publicKeyModulus = calloc(modulusLength, sizeof(UCHAR));
			UCHAR* publicKeyExponent = calloc(exponentLength, sizeof(UCHAR));
			BOOL leadingZeros = TRUE;
			int modulusOffset = 0;
			if (publicKeyModulus != NULL) {
				memcpy(publicKeyModulus, &sptwb_ex.ucDataBuf[14], modulusLength);
				for (int i = 0; i < modulusLength; i++)
				{
					if (leadingZeros) {
						leadingZeros = publicKeyModulus[i] == 0;
						if (leadingZeros) {
							modulusOffset++;
							continue;
						}
						else
						{
							break;
						}
					}
				}
			}
			leadingZeros = TRUE;
			int exponentOffset = 0;
			if (publicKeyExponent != NULL) {
				memcpy(publicKeyExponent, &sptwb_ex.ucDataBuf[14 + modulusLength], exponentLength);
				for (int i = 0; i < exponentLength; i++)
				{
					if (leadingZeros) {
						leadingZeros = publicKeyExponent[i] == 0;
						if (leadingZeros) {
							exponentOffset++;
							continue;
						}
						else
						{
							break;
						}
					}
				}
			}
			// Convert the public key to hex-encoded DER if the following are true:
			// 1) The modulus is 256 bytes (2048-bit),
			// 2) The exponent is 3 bytes long (99.5% of RSA keys use e=65537=0x010001)
			// NB: A 2040-bit (255 byte) modulus fails to meet these conditions - DER forbids integers starting 0x0000
			if (modulusOffset == 0 && exponentOffset == (exponentLength - 3))
			{
				// ASN.1
				printf("DER: 30820122"); // 30=SEQUENCE, 82=multibyte length (0x80) using 2 bytes (0x2), 0122=length
				// RSA Encryption (Public Key) - OID 1.2.840.113549.1.1.1
				printf("300D"); // 30=SEQUENCE, 0D=length
				printf("0609"); // 06=OID, 09=length
				printf("2A"); // 2A=1.2 (2A/28.2A%28),
				printf("864886F70D010101"); // 8648=840 (VLQ/Base-128), 86F70D=113549 (VLQ/Base-128), 010101=1.1.1 (VLQ/Base-128)
				printf("0500"); // 05=NULL, 00=length
				// Bit string wrapper
				printf("0382010F00"); // 03=BIT STRING, 82=multibyte length using 2 bytes, 010F=length, 00=unused (trailing) bits in last octet of bit string
				// Modulus + exponent
				printf("3082010A"); // 30=SEQUENCE, 82=multibyte length using 2 bytes, 010A=length
				// Modulus integer
				printf("02820101"); // 02=INTEGER, 82=multibyte length using 2 bytes, 0101=length
				printf("00"); // 00=leading zero so unsigned integer is represented as a positive signed integer
				for (int i = 0; i < 256; i++)
				{
					printf("%X", (publicKeyModulus[i] & 0xFF) >> 4); // Upper 4 bits
					printf("%X", publicKeyModulus[i] & 0x0F); // Lower 4 bits
				}
				// Exponent integer
				printf("02%02X", 256 - exponentOffset); // 02=INTEGER, %02X=length
				for (int i = exponentOffset; i < 256; i++)
				{
					printf("%X", (publicKeyExponent[i] & 0xFF) >> 4); // Upper 4 bits
					printf("%X", publicKeyExponent[i] & 0x0F); // Lower 4 bits
				}
				printf("\n");
				wrappedDescriptorsLength = 4 + logicalUnitIdentifierLength + 4 + 2;
				wrappedDescripters = calloc(wrappedDescriptorsLength, sizeof(UCHAR));
				wrappedDescripters[2] = (logicalUnitIdentifierLength >> 8) & 0xF;
				wrappedDescripters[3] = logicalUnitIdentifierLength & 0xF;
				memcpy(wrappedDescripters + 4, logicalUnitIdentifier, logicalUnitIdentifierLength);
				wrappedDescripters[4 + logicalUnitIdentifierLength + 0] = 0x4;
				wrappedDescripters[4 + logicalUnitIdentifierLength + 3] = 0x2;
				wrappedDescripters[4 + logicalUnitIdentifierLength + 4] = 0x1;
				printf("Wrapped Key Descriptors: ");
				for (int i = 0; i < wrappedDescriptorsLength; i++)
				{
					printf("%X", (wrappedDescripters[i] & 0xFF) >> 4); // Upper 4 bits
					printf("%X", wrappedDescripters[i] & 0x0F); // Lower 4 bits
				}
				printf("\n\n");
			}
			else
			{
				fprintf(stderr, "Only RSA-2048 public keys with a 256 byte modulus and 3 byte exponent are currently supported.\n");
			}
			free(publicKeyModulus);
			free(publicKeyExponent);
		}

		//  PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);

	}


	if (capRfc3447 && keyFormat == SPIN_TAPE_KEY_FORMAT_WRAPPED && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		int wrappedKeyLength = keyLength / 2;
		printf("Wrapped key length: %d bytes\n", wrappedKeyLength);

		if (aesGcmAlgorithmIndex == -1)
		{
			fprintf(stderr, "AES-GCM algorithm index not found.\n\n");
			CloseHandle(fileHandle);
			return;
		}

		printf("AES-GCM algorithm index: 0x%02x\n\n", aesGcmAlgorithmIndex);

		int kadTotalLength = 0;
		PPLAIN_KEY_DESCRIPTOR kad = NULL;
		if (!noKey) {
			char* kadName = "Test2";
			int kadLength = (int)strlen(kadName);
			kadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[kadLength]);
			kad = malloc(kadTotalLength);
			ZeroMemory(kad, sizeof(PLAIN_KEY_DESCRIPTOR));
			kad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH; // TODO: Check length is less than *Maximum Authenticated Key-Associated Data Bytes*
			kad->Length[0] = (kadLength & 0xFF00) >> 8;
			kad->Length[1] = kadLength & 0xFF;
			memcpy(kad->Descriptor, kadName, kadLength);
			printf("KAD Descriptor with length %d:\n\n", kadTotalLength);
			PrintDataBuffer((PUCHAR)kad, kadTotalLength);
		}

		KEY_HEADER keyHeader = { 0 };
		keyHeader.PageCode[0] = (SPOUT_TAPE_SET_DATA_ENCRYPTION >> 8) & 0xFF;
		keyHeader.PageCode[1] = SPOUT_TAPE_SET_DATA_ENCRYPTION & 0xFF;
		keyHeader.Scope = 0x2;
		//keyHeader.CKOD = 0b1;
		//keyHeader.CKORP = 0b1;
		//keyHeader.CKORL = 0b1;
		keyHeader.EncryptionMode = 0x2;
		keyHeader.DecriptionMode = 0x2;
		keyHeader.AlgorithmIndex = aesGcmAlgorithmIndex;
		keyHeader.KeyFormat = (UCHAR)keyFormat;
		keyHeader.KADFormat = SPOUT_TAPE_KAD_FORMAT_ASCII;

		int wrappedKeyTotalLength = 4 + wrappedDescriptorsLength + 2 + wrappedKeyLength + 2;
		UCHAR* wrappedKey = calloc(wrappedKeyTotalLength, sizeof(UCHAR));
		wrappedKey[0] = (keyType >> 8) & 0xFF;
		wrappedKey[1] = keyType & 0xFF;
		wrappedKey[2] = (wrappedDescriptorsLength >> 8) & 0xFF;
		wrappedKey[3] = wrappedDescriptorsLength & 0xFF;
		memcpy(wrappedKey + 4, wrappedDescripters, wrappedDescriptorsLength);
		wrappedKey[4 + wrappedDescriptorsLength + 0] = (wrappedKeyLength >> 8) & 0xFF;
		wrappedKey[4 + wrappedDescriptorsLength + 1] = wrappedKeyLength & 0xFF;
		UCHAR temp[3] = { 0 };
		for (int i = 0; i < wrappedKeyLength; i++)
		{
			memcpy(temp, &key[i * 2], 2);
			wrappedKey[4 + wrappedDescriptorsLength + 2 + i] = strtol((char*)temp, NULL, 16) & 0xFF;
		}

		int pageLength = sizeof(KEY_HEADER) - 4 + 2 + wrappedKeyTotalLength + kadTotalLength;
		keyHeader.PageLength[0] = (pageLength >> 8) & 0xFF;
		keyHeader.PageLength[1] = pageLength & 0xFF;

		length = ResetSrbOut(&sptwb_ex, CDB12GENERIC_LENGTH);
		struct _SECURITY_PROTOCOL_OUT spout = { '\0' };
		spout.OperationCode = SCSIOP_SECURITY_PROTOCOL_OUT;
		spout.SecurityProtocol = SECURITY_PROTOCOL_TAPE; // tape encryption
		spout.SecurityProtocolSpecific[0] = (SPOUT_TAPE_SET_DATA_ENCRYPTION >> 8) & 0xFF; // device server key wrapping public key page
		spout.SecurityProtocolSpecific[1] = SPOUT_TAPE_SET_DATA_ENCRYPTION & 0xFF;
		int allocationLength = 4 + pageLength;
		spout.AllocationLength[0] = (allocationLength >> 24) & 0xFF;
		spout.AllocationLength[1] = (allocationLength >> 16) & 0xFF;
		spout.AllocationLength[2] = (allocationLength >> 8) & 0xFF;
		spout.AllocationLength[3] = allocationLength & 0xFF;
		memcpy(sptwb_ex.spt.Cdb, &spout, sizeof(struct _SECURITY_PROTOCOL_OUT));
		printf("Security Protocol Out:\n\n");
		PrintDataBuffer(sptwb_ex.spt.Cdb, sizeof(spout));
		sptwb_ex.spt.DataOutTransferLength = allocationLength;

		memcpy(sptwb_ex.ucDataBuf, &keyHeader, sizeof(keyHeader));
		sptwb_ex.ucDataBuf[sizeof(keyHeader) + 0] = (wrappedKeyTotalLength >> 8) & 0xFF;
		sptwb_ex.ucDataBuf[sizeof(keyHeader) + 1] = wrappedKeyTotalLength & 0xFF;
		memcpy(sptwb_ex.ucDataBuf + sizeof(keyHeader) + 2, wrappedKey, wrappedKeyTotalLength);
		memcpy(sptwb_ex.ucDataBuf + sizeof(keyHeader) + 2 + wrappedKeyTotalLength, kad, kadTotalLength);

		printf("Buffer length: %d (0x%02x)\n\n", allocationLength, allocationLength);
		printf("SRB length: %d (0x%02x)\n\n", length, length);


		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		printf("Buffer:\n\n");
		PrintDataBuffer((PUCHAR)&sptwb_ex.ucDataBuf, sptwb_ex.spt.DataOutTransferLength);

		//PrintSenseInfo(&sptdwb_ex.sptd);
		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X, SCSI Status: 0x%02x\n\n", status, sptwb_ex.spt.ScsiStatus);
		}
		PrintStatusResultsEx(status, returned, &sptwb_ex, returned);

	}


	if ((testKey || noKey) && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		if (aesGcmAlgorithmIndex == -1)
		{
			fprintf(stderr, "AES-GCM algorithm index not found.\n\n");
			CloseHandle(fileHandle);
			return;
		}

		printf("AES-GCM algorithm index: 0x%02x\n\n", aesGcmAlgorithmIndex);

		int kadTotalLength = 0;
		PPLAIN_KEY_DESCRIPTOR kad = NULL;
		if (!noKey) {
			char* kadName = "Test2";
			int kadLength = (int)strlen(kadName);
			kadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[kadLength]);
			kad = malloc(kadTotalLength);
			ZeroMemory(kad, sizeof(PLAIN_KEY_DESCRIPTOR));
			kad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH; // TODO: Check length is less than *Maximum Authenticated Key-Associated Data Bytes*
			kad->Length[0] = (kadLength & 0xFF00) >> 8;
			kad->Length[1] = kadLength & 0xFF;
			memcpy(kad->Descriptor, kadName, kadLength);
			printf("KAD Descriptor with length %d:\n\n", kadTotalLength);
			PrintDataBuffer((PUCHAR)kad, kadTotalLength);
		}

		int plainKeyTotalLength = noKey ? FIELD_OFFSET(PLAIN_KEY, Key[0]) : FIELD_OFFSET(PLAIN_KEY, KADList[kadTotalLength]);
		PPLAIN_KEY plainKey = malloc(plainKeyTotalLength);
		ZeroMemory(plainKey, plainKeyTotalLength);
		plainKey->PageCode[0] = (SPOUT_TAPE_SET_DATA_ENCRYPTION >> 8) & 0xFF;
		plainKey->PageCode[1] = SPOUT_TAPE_SET_DATA_ENCRYPTION & 0xFF;
		plainKey->Scope = 0x2;
		//plainKey->CKOD = 0b1;
		//plainKey->CKORP = 0b1;
		//plainKey->CKORL = 0b1;
		plainKey->EncryptionMode = noKey ? 0x0 : 0x2;
		plainKey->DecriptionMode = noKey ? 0x0 : 0x2;
		plainKey->AlgorithmIndex = aesGcmAlgorithmIndex;
		if (keyFormat >= 0)
		{
			plainKey->KeyFormat = (UCHAR)keyFormat;
		}
		plainKey->KADFormat = noKey ? 0x0 : SPOUT_TAPE_KAD_FORMAT_ASCII;
		plainKey->KeyLength[1] = noKey ? 0x0 : 0x20;

		if (!noKey) {
			for (int i = 0; i < 32; i++)
			{
				plainKey->Key[i] = (UCHAR)(i + 0x10);
			}
			memcpy(plainKey->KADList, kad, kadTotalLength);
			free(kad);
		}

		plainKey->PageLength[0] = ((plainKeyTotalLength - 4) & 0xFF00) >> 8;
		plainKey->PageLength[1] = (plainKeyTotalLength - 4) & 0xFF;
		printf("Set plain key with %d byte KAD list:\n\n", kadTotalLength);
		PrintDataBuffer((PUCHAR)plainKey, plainKeyTotalLength);

		length = ResetSrbOut(&sptwb_ex, CDB12GENERIC_LENGTH);
		struct _SECURITY_PROTOCOL_OUT spout = { '\0' };
		spout.OperationCode = SCSIOP_SECURITY_PROTOCOL_OUT;
		spout.SecurityProtocol = SECURITY_PROTOCOL_TAPE; // tape encryption
		spout.SecurityProtocolSpecific[0] = (SPOUT_TAPE_SET_DATA_ENCRYPTION >> 8) & 0xFF; // device server key wrapping public key page
		spout.SecurityProtocolSpecific[1] = SPOUT_TAPE_SET_DATA_ENCRYPTION & 0xFF;
		spout.AllocationLength[0] = (plainKeyTotalLength >> 24) & 0xFF;
		spout.AllocationLength[1] = (plainKeyTotalLength >> 16) & 0xFF;
		spout.AllocationLength[2] = (plainKeyTotalLength >> 8) & 0xFF;
		spout.AllocationLength[3] = plainKeyTotalLength & 0xFF;
		memcpy(sptwb_ex.spt.Cdb, &spout, sizeof(struct _SECURITY_PROTOCOL_OUT));
		printf("Security Protocol Out:\n\n");
		PrintDataBuffer(sptwb_ex.spt.Cdb, sizeof(spout));

		memcpy(sptwb_ex.ucDataBuf, plainKey, plainKeyTotalLength);
		free(plainKey);
		sptwb_ex.spt.DataOutTransferLength = plainKeyTotalLength;

		printf("Buffer length: %d (0x%02x)\n\n", plainKeyTotalLength, plainKeyTotalLength);
		printf("SRB length: %d (0x%02x)\n\n", length, length);

		status = DeviceIoControl(fileHandle,
			IOCTL_SCSI_PASS_THROUGH_EX,
			&sptwb_ex,
			sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
			&sptwb_ex,
			length,
			&returned,
			FALSE);

		printf("Cdb:\n\n");
		PrintDataBuffer(sptwb_ex.spt.Cdb, sptwb_ex.spt.CdbLength);
		printf("Buffer:\n\n");
		PrintDataBuffer((PUCHAR)&sptwb_ex.ucDataBuf, sptwb_ex.spt.DataOutTransferLength);

		//PrintSenseInfo(&sptdwb_ex.sptd);
		if (!status || sptwb_ex.spt.ScsiStatus != SCSISTAT_GOOD)
		{
			printf("Status: 0x%02X, SCSI Status: 0x%02x\n\n", status, sptwb_ex.spt.ScsiStatus);
		}
		PrintStatusResultsEx(status, returned, &sptwb_ex, returned);
	}


	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		SecurityProtocolInSrbIn(fileHandle, &sptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_STATUS, "Encryption Status");
		SecurityProtocolInSrbIn(fileHandle, &sptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS, "Next Block Encryption Status");
		SecurityProtocolInSrbIn(fileHandle, &sptwb_ex, SECURITY_PROTOCOL_INFO, SPIN_CERTIFICATE_DATA, "Certificate Data");
		SecurityProtocolInSrbIn(fileHandle, &sptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_MANAGEMENT_CAPABILITIES, "Data Encryption Management Capabilities");
	}

	if (pUnAlignedBuffer != NULL) {
		free(pUnAlignedBuffer);
	}
	if (logicalUnitIdentifier != NULL) {
		free(logicalUnitIdentifier);
	}
	if (wrappedDescripters != NULL) {
		free(wrappedDescripters);
	}
	CloseHandle(fileHandle);
}

VOID
SecurityProtocolInSrbIn(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode, CHAR* cdbDescription)
{
	UCHAR cdbLength = GetCdbLength(securityProtocol);
	if (cdbLength == 0)
	{
		return;
	}
	UCHAR multibyteParams[13] = { '\0' };
	multibyteParams[1] = pageCode; // supported key formats page
	multibyteParams[4] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
	multibyteParams[5] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
	multibyteParams[6] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
	multibyteParams[7] = SPTWB_DATA_LENGTH & 0xFF;

	SimpleSrbIn(fileHandle, psptwb_ex, SCSIOP_SECURITY_PROTOCOL_IN, securityProtocol, multibyteParams, cdbDescription);
}

VOID
SimpleSrbIn(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode, UCHAR params, UCHAR* multibyteParams, CHAR* cdbDescription)
{
	ULONG returned = 0;
	UCHAR cdbLength = GetCdbLength(opCode);
	if (cdbLength == 0) {
		return;
	}
	ULONG length = ResetSrbIn(psptwb_ex, cdbLength);
	psptwb_ex->spt.Cdb[0] = opCode;
	psptwb_ex->spt.Cdb[1] = params;
	memcpy(psptwb_ex->spt.Cdb + 2, multibyteParams, cdbLength - 3);
	psptwb_ex->spt.Cdb[cdbLength - 1] = '\0';

	BOOL status = DeviceIoControl(fileHandle,
		IOCTL_SCSI_PASS_THROUGH_EX,
		psptwb_ex,
		sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
		psptwb_ex,
		length,
		&returned,
		FALSE);

	printf("%s:\n\n", cdbDescription);
	PrintDataBuffer(psptwb_ex->ucDataBuf, psptwb_ex->spt.DataInTransferLength);

	if (!status || psptwb_ex->spt.ScsiStatus != SCSISTAT_GOOD)
	{
		printf("Status: 0x%02X\n\n", psptwb_ex->spt.ScsiStatus);
		PrintStatusResultsEx(status, returned, psptwb_ex, length);
	}
}

UCHAR
GetCdbLength(UCHAR opCode)
{
	UCHAR groupCode = (opCode & 0xE0) >> 5;
	switch (groupCode)
	{
	case 0:
	case 3:
		return CDB6GENERIC_LENGTH;
	case 1:
	case 2:
		return CDB10GENERIC_LENGTH;
	case 5:
		return CDB12GENERIC_LENGTH;
	case 4: // 16 byte commands
	case 6: // vendor-unique commands
	case 7: // not supported
	default:
		return 0;
	}
}

int
ResetSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, int cdbLength)
{
	ZeroMemory(psptwb_ex, sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
	psptwb_ex->spt.Version = 0;
	psptwb_ex->spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
	psptwb_ex->spt.ScsiStatus = 0;
	psptwb_ex->spt.CdbLength = cdbLength;
	psptwb_ex->spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
	psptwb_ex->spt.SenseInfoLength = SPT_SENSE_LENGTH;
	psptwb_ex->spt.DataOutTransferLength = 0;
	psptwb_ex->spt.DataInTransferLength = 4 << 8;
	psptwb_ex->spt.DataDirection = SCSI_IOCTL_DATA_IN;
	psptwb_ex->spt.TimeOutValue = 2;
	psptwb_ex->spt.StorAddressOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, StorAddress);
	psptwb_ex->StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
	psptwb_ex->StorAddress.Port = 0;
	psptwb_ex->StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
	psptwb_ex->StorAddress.Path = 0;
	psptwb_ex->StorAddress.Target = 0;
	psptwb_ex->StorAddress.Lun = 0;
	psptwb_ex->spt.SenseInfoOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucSenseBuf);
	psptwb_ex->spt.DataOutBufferOffset = 0;
	psptwb_ex->spt.DataInBufferOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf);
	return offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf) +
		psptwb_ex->spt.DataInTransferLength;
}

int
ResetSrbOut(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, int cdbLength)
{
	ZeroMemory(psptwb_ex, sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
	psptwb_ex->spt.Version = 0;
	psptwb_ex->spt.Length = sizeof(SCSI_PASS_THROUGH_EX);
	psptwb_ex->spt.ScsiStatus = 0;
	psptwb_ex->spt.CdbLength = cdbLength;
	psptwb_ex->spt.StorAddressLength = sizeof(STOR_ADDR_BTL8);
	psptwb_ex->spt.SenseInfoLength = SPT_SENSE_LENGTH;
	psptwb_ex->spt.DataOutTransferLength = 4 << 8;
	psptwb_ex->spt.DataInTransferLength = 0;
	psptwb_ex->spt.DataDirection = SCSI_IOCTL_DATA_OUT;
	psptwb_ex->spt.TimeOutValue = 20;
	psptwb_ex->spt.StorAddressOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, StorAddress);
	psptwb_ex->StorAddress.Type = STOR_ADDRESS_TYPE_BTL8;
	psptwb_ex->StorAddress.Port = 0;
	psptwb_ex->StorAddress.AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
	psptwb_ex->StorAddress.Path = 0;
	psptwb_ex->StorAddress.Target = 0;
	psptwb_ex->StorAddress.Lun = 0;
	psptwb_ex->spt.SenseInfoOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucSenseBuf);
	psptwb_ex->spt.DataOutBufferOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf);
	psptwb_ex->spt.DataInBufferOffset = 0;
	return offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf) +
		psptwb_ex->spt.DataOutTransferLength;
}

VOID
PrintError(ULONG ErrorCode)
{
	CHAR errorBuffer[80];
	ULONG count;

	count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		ErrorCode,
		0,
		errorBuffer,
		sizeof(errorBuffer),
		NULL
	);

	if (count != 0) {
		printf("%s\n", errorBuffer);
	}
	else {
		printf("Format message failed.  Error: %d\n", GetLastError());
	}
}

VOID
PrintDataBuffer(_In_reads_(BufferLength) PUCHAR DataBuffer, _In_ ULONG BufferLength)
{
	ULONG Cnt;

	printf("      00  01  02  03  04  05  06  07   08  09  0A  0B  0C  0D  0E  0F\n");
	printf("      ---------------------------------------------------------------\n");
	for (Cnt = 0; Cnt < BufferLength; Cnt++) {
		if ((Cnt) % 16 == 0) {
			printf(" %03X  ", Cnt);
		}
		printf("%02X  ", DataBuffer[Cnt]);
		if ((Cnt + 1) % 8 == 0) {
			printf(" ");
		}
		if ((Cnt + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("\n\n");
}

VOID
PrintAdapterDescriptor(PSTORAGE_ADAPTER_DESCRIPTOR AdapterDescriptor)
{
	ULONG trueMaximumTransferLength;
	LPCSTR busType;

	if (AdapterDescriptor->BusType < NUMBER_OF_BUS_TYPE_STRINGS) {
		busType = BusTypeStrings[AdapterDescriptor->BusType];
	}
	else {
		busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS - 1];
	}

	// subtract one page, as transfers do not always start on a page boundary
	if (AdapterDescriptor->MaximumPhysicalPages > 1) {
		trueMaximumTransferLength = AdapterDescriptor->MaximumPhysicalPages - 1;
	}
	else {
		trueMaximumTransferLength = 1;
	}
	// make it into a byte value
	trueMaximumTransferLength <<= PAGE_SHIFT;

	// take the minimum of the two
	if (trueMaximumTransferLength > AdapterDescriptor->MaximumTransferLength) {
		trueMaximumTransferLength = AdapterDescriptor->MaximumTransferLength;
	}

	// always allow at least a single page transfer
	if (trueMaximumTransferLength < PAGE_SIZE) {
		trueMaximumTransferLength = PAGE_SIZE;
	}

	puts("\n            ***** STORAGE ADAPTER DESCRIPTOR DATA *****");
	printf("              Version: %08x\n"
		"            TotalSize: %08x\n"
		"MaximumTransferLength: %08x (bytes)\n"
		" MaximumPhysicalPages: %08x\n"
		"  TrueMaximumTransfer: %08x (bytes)\n"
		"        AlignmentMask: %08x\n"
		"       AdapterUsesPio: %s\n"
		"     AdapterScansDown: %s\n"
		"      CommandQueueing: %s\n"
		"  AcceleratedTransfer: %s\n"
		"             Bus Type: %s\n"
		"    Bus Major Version: %04x\n"
		"    Bus Minor Version: %04x\n",
		AdapterDescriptor->Version,
		AdapterDescriptor->Size,
		AdapterDescriptor->MaximumTransferLength,
		AdapterDescriptor->MaximumPhysicalPages,
		trueMaximumTransferLength,
		AdapterDescriptor->AlignmentMask,
		BOOLEAN_TO_STRING(AdapterDescriptor->AdapterUsesPio),
		BOOLEAN_TO_STRING(AdapterDescriptor->AdapterScansDown),
		BOOLEAN_TO_STRING(AdapterDescriptor->CommandQueueing),
		BOOLEAN_TO_STRING(AdapterDescriptor->AcceleratedTransfer),
		busType,
		AdapterDescriptor->BusMajorVersion,
		AdapterDescriptor->BusMinorVersion);




	printf("\n\n");
}

VOID
PrintDeviceDescriptor(PSTORAGE_DEVICE_DESCRIPTOR DeviceDescriptor)
{
	LPCSTR vendorId = "";
	LPCSTR productId = "";
	LPCSTR productRevision = "";
	LPCSTR serialNumber = "";
	LPCSTR busType;

	if ((ULONG)DeviceDescriptor->BusType < NUMBER_OF_BUS_TYPE_STRINGS) {
		busType = BusTypeStrings[DeviceDescriptor->BusType];
	}
	else {
		busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS - 1];
	}

	if ((DeviceDescriptor->ProductIdOffset != 0) &&
		(DeviceDescriptor->ProductIdOffset != -1)) {
		productId = (LPCSTR)(DeviceDescriptor);
		productId += (ULONG_PTR)DeviceDescriptor->ProductIdOffset;
	}
	if ((DeviceDescriptor->VendorIdOffset != 0) &&
		(DeviceDescriptor->VendorIdOffset != -1)) {
		vendorId = (LPCSTR)(DeviceDescriptor);
		vendorId += (ULONG_PTR)DeviceDescriptor->VendorIdOffset;
	}
	if ((DeviceDescriptor->ProductRevisionOffset != 0) &&
		(DeviceDescriptor->ProductRevisionOffset != -1)) {
		productRevision = (LPCSTR)(DeviceDescriptor);
		productRevision += (ULONG_PTR)DeviceDescriptor->ProductRevisionOffset;
	}
	if ((DeviceDescriptor->SerialNumberOffset != 0) &&
		(DeviceDescriptor->SerialNumberOffset != -1)) {
		serialNumber = (LPCSTR)(DeviceDescriptor);
		serialNumber += (ULONG_PTR)DeviceDescriptor->SerialNumberOffset;
	}


	puts("\n            ***** STORAGE DEVICE DESCRIPTOR DATA *****");
	printf("              Version: %08x\n"
		"            TotalSize: %08x\n"
		"           DeviceType: %08x\n"
		"   DeviceTypeModifier: %08x\n"
		"       RemovableMedia: %s\n"
		"      CommandQueueing: %s\n"
		"            Vendor Id: %s\n"
		"           Product Id: %s\n"
		"     Product Revision: %s\n"
		"        Serial Number: %s\n"
		"             Bus Type: %s\n"
		"       Raw Properties: %s\n",
		DeviceDescriptor->Version,
		DeviceDescriptor->Size,
		DeviceDescriptor->DeviceType,
		DeviceDescriptor->DeviceTypeModifier,
		BOOLEAN_TO_STRING(DeviceDescriptor->RemovableMedia),
		BOOLEAN_TO_STRING(DeviceDescriptor->CommandQueueing),
		vendorId,
		productId,
		productRevision,
		serialNumber,
		busType,
		(DeviceDescriptor->RawPropertiesLength ? "Follows" : "None"));
	if (DeviceDescriptor->RawPropertiesLength != 0) {
		PrintDataBuffer(DeviceDescriptor->RawDeviceProperties,
			DeviceDescriptor->RawPropertiesLength);
	}
	printf("\n\n");
}

VOID
PrintStatusResults(
	BOOL status, DWORD returned, PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb,
	ULONG length)
{
	ULONG errorCode;

	if (!status) {
		printf("Error: %d  ",
			errorCode = GetLastError());
		PrintError(errorCode);
		return;
	}
	if (psptwb->spt.ScsiStatus) {
		PrintSenseInfo(psptwb);
		return;
	}
	else {
		printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
			psptwb->spt.ScsiStatus, returned);
		printf("Data buffer length: %Xh\n\n\n",
			psptwb->spt.DataTransferLength);
		PrintDataBuffer((PUCHAR)psptwb, length);
	}
}

VOID
PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb)
{
	UCHAR i;

	printf("Scsi status: %02Xh\n\n", psptwb->spt.ScsiStatus);
	if (psptwb->spt.SenseInfoLength == 0) {
		return;
	}
	printf("Sense Info -- consult SCSI spec for details\n");
	printf("-------------------------------------------------------------\n");
	for (i = 0; i < psptwb->spt.SenseInfoLength; i++) {
		printf("%02X ", psptwb->ucSenseBuf[i]);
	}
	printf("\n\n");
}

VOID
PrintStatusResultsEx(
	BOOL status, DWORD returned, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex,
	ULONG length)
{
	ULONG errorCode;

	if (!status) {
		printf("Error: %d  ",
			errorCode = GetLastError());
		PrintError(errorCode);
		return;
	}
	if (psptwb_ex->spt.ScsiStatus) {
		PrintSenseInfoEx(psptwb_ex);
		return;
	}
	else {
		printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
			psptwb_ex->spt.ScsiStatus, returned);
		printf("DataOut buffer length: %Xh\n"
			"DataIn buffer length: %Xh\n\n\n",
			psptwb_ex->spt.DataOutTransferLength,
			psptwb_ex->spt.DataInTransferLength);
		PrintDataBuffer((PUCHAR)psptwb_ex, length);
	}
}

VOID
PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex)
{
	ULONG i;

	printf("Scsi status: %02Xh\n\n", psptwb_ex->spt.ScsiStatus);
	if (psptwb_ex->spt.SenseInfoLength == 0) {
		return;
	}
	printf("Sense Info -- consult SCSI spec for details\n");
	printf("-------------------------------------------------------------\n");
	for (i = 0; i < psptwb_ex->spt.SenseInfoLength; i++) {
		printf("%02X ", psptwb_ex->ucSenseBuf[i]);
	}
	printf("\n\n");
}

_Success_(return)
BOOL
QueryPropertyForDevice(
	_In_ IN HANDLE DeviceHandle,
	_Out_ OUT PULONG AlignmentMask,
	_Out_ OUT PUCHAR SrbType,
	_Out_ OUT PSTORAGE_BUS_TYPE StorageBusType
)
{
	PSTORAGE_ADAPTER_DESCRIPTOR adapterDescriptor = NULL;
	PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = NULL;
	STORAGE_DESCRIPTOR_HEADER header = { 0 };

	BOOL ok = TRUE;
	BOOL failed = TRUE;
	ULONG i;

	*AlignmentMask = 0; // default to no alignment
	*SrbType = SRB_TYPE_SCSI_REQUEST_BLOCK; // default to SCSI_REQUEST_BLOCK
	*StorageBusType = BusTypeUnknown;

	// Loop twice:
	//  First, get size required for storage adapter descriptor
	//  Second, allocate and retrieve storage adapter descriptor
	//  Third, get size required for storage device descriptor
	//  Fourth, allocate and retrieve storage device descriptor
	for (i = 0; i < 4; i++) {

		PVOID buffer = NULL;
		ULONG bufferSize = 0;
		ULONG returnedData;

		STORAGE_PROPERTY_QUERY query = { 0 };

		switch (i) {
		case 0: {
			query.QueryType = PropertyStandardQuery;
			query.PropertyId = StorageAdapterProperty;
			bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
			buffer = &header;
			break;
		}
		case 1: {
			query.QueryType = PropertyStandardQuery;
			query.PropertyId = StorageAdapterProperty;
			bufferSize = header.Size;
			if (bufferSize != 0) {
				adapterDescriptor = LocalAlloc(LPTR, bufferSize);
				if (adapterDescriptor == NULL) {
					goto Cleanup;
				}
			}
			buffer = adapterDescriptor;
			break;
		}
		case 2: {
			query.QueryType = PropertyStandardQuery;
			query.PropertyId = StorageDeviceProperty;
			bufferSize = sizeof(STORAGE_DESCRIPTOR_HEADER);
			buffer = &header;
			break;
		}
		case 3: {
			query.QueryType = PropertyStandardQuery;
			query.PropertyId = StorageDeviceProperty;
			bufferSize = header.Size;

			if (bufferSize != 0) {
				deviceDescriptor = LocalAlloc(LPTR, bufferSize);
				if (deviceDescriptor == NULL) {
					goto Cleanup;
				}
			}
			buffer = deviceDescriptor;
			break;
		}
		}

		// buffer can be NULL if the property queried DNE.
		if (buffer != NULL) {
			RtlZeroMemory(buffer, bufferSize);

			// all setup, do the ioctl
			ok = DeviceIoControl(DeviceHandle,
				IOCTL_STORAGE_QUERY_PROPERTY,
				&query,
				sizeof(STORAGE_PROPERTY_QUERY),
				buffer,
				bufferSize,
				&returnedData,
				FALSE);
			if (!ok) {
				if (GetLastError() == ERROR_MORE_DATA) {
					// this is ok, we'll ignore it here
				}
				else if (GetLastError() == ERROR_INVALID_FUNCTION) {
					// this is also ok, the property DNE
				}
				else if (GetLastError() == ERROR_NOT_SUPPORTED) {
					// this is also ok, the property DNE
				}
				else {
					// some unexpected error -- exit out
					goto Cleanup;
				}
				// zero it out, just in case it was partially filled in.
				RtlZeroMemory(buffer, bufferSize);
			}
		}
	} // end i loop

	// adapterDescriptor is now allocated and full of data.
	// deviceDescriptor is now allocated and full of data.

	if (adapterDescriptor == NULL) {
		printf("   ***** No adapter descriptor supported on the device *****\n");
	}
	else {
		PrintAdapterDescriptor(adapterDescriptor);
		*AlignmentMask = adapterDescriptor->AlignmentMask;
		*SrbType = adapterDescriptor->SrbType;
	}

	if (deviceDescriptor == NULL) {
		printf("   ***** No device descriptor supported on the device  *****\n");
	}
	else {
		PrintDeviceDescriptor(deviceDescriptor);
		*StorageBusType = deviceDescriptor->BusType;
	}

	failed = FALSE;

Cleanup:
	if (adapterDescriptor != NULL) {
		LocalFree(adapterDescriptor);
	}
	if (deviceDescriptor != NULL) {
		LocalFree(deviceDescriptor);
	}
	return (!failed);

}

