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
#pragma comment(lib, "SetupAPI.lib")
#include <setupapi.h>
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
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

LPCSTR CfgPCapableStrings[] = {
	"Unknown",
	"False",
	"True",
	"Unknown"
};

LPCSTR EncryptionCapableStrings[] = {
	"No Capability",
	"Software",
	"Hardware",
	"Capable with External Control"
};

LPCSTR AvfclpCapableStrings[] = {
	"Not applicable or no tape loaded",
	"Not valid at current logical position",
	"Valid at current logical position",
	"Unknown"
};

LPCSTR DkadCapableStrings[] = {
	"Unspecified",
	"Required",
	"Not Allowed",
	"Capable"
};

LPCSTR EemcCapableStrings[] = {
	"Unspecified",
	"False",
	"True",
	"Unspecified"
};

LPCSTR KadFormatStrings[] = {
	"Unspecified",
	"Binary",
	"ASCII",
	"Unexpected value"
};
#define NUMBER_OF_KAD_FORMAT_STRINGS (sizeof(KadFormatStrings)/sizeof(KadFormatStrings[0]))

LPCSTR NextBlockEncryptionStatusStrings[] = {
	"Cannot be determined.",
	"Cannot be determined at this time.",
	"Not a logical block.",
	"Not encrypted.",
	"Encrypted, unsupported encryption algorithm.",
	"Encrypted, supported encryption algorithm, can decrypt.",
	"Encrypted, supported encryption algorithm, cannot decrypt.",
	"Unexpected value"
};
#define NUMBER_OF_NEXT_BLOCK_ENCRYPTION_STATUS_STRINGS (sizeof(NextBlockEncryptionStatusStrings)/sizeof(NextBlockEncryptionStatusStrings[0]))

LPCSTR SenseKeyStrings[] = {
	"NO SENSE",
	"RECOVERED ERROR",
	"NOT READY",
	"MEDIUM ERROR",
	"HARDWARE ERROR",
	"ILLEGAL REQUEST",
	"UNIT ATTENTION",
	"DATA PROTECT",
	"BLANK CHECK",
	"VENDOR SPECIFIC",
	"COPY ABORTED",
	"ABORTED COMMAND",
	"EQUAL",
	"VOLUME OVERFLOW",
	"MISCOMPARE",
	"UNKNOWN"
};

LPCSTR EncryptionModeStrings[] = {
	"Disabled",
	"External",
	"Encrypt",
	"Unexpected value"
};

LPCSTR DecryptionModeStrings[] = {
	"Disabled",
	"External",
	"Decrypt",
	"Mixed"
};

LPCSTR EncryptionParametersControlStings[] = {
	"Unspecified",
	"Non-exclusive external data encryption control",
	"Exclusive SSC device server control",
	"Exclusive ADC device server control",
	"Exclusive management interface control"
};

LPCSTR EncryptionParametersScopeStrings[] = {
	"Public",
	"Local",
	"All I_T Nexus"
};

/// <summary>
/// Uses SCSI Pass Through Interface (SPTI) to communicate with an LTO tape drive
/// </summary>
/// <param name="argc">Number of command line parameters</param>
/// <param name="argv">Command line parameters</param>
/// <returns>-1 on some errors, usually 0</returns>
int
__cdecl
main(
	_In_ int argc,
	_In_z_ char* argv[]
)

{
	BOOL status = 0;
	DWORD accessMode = GENERIC_WRITE | GENERIC_READ;
	DWORD shareMode = FILE_SHARE_READ;
	HANDLE fileHandle = NULL;
	ULONG alignmentMask = 0; // default == no alignment requirement
	UCHAR srbType = SRB_TYPE_SCSI_REQUEST_BLOCK; // default == SRB_TYPE_SCSI_REQUEST_BLOCK
	STORAGE_BUS_TYPE storageBusType = BusTypeUnknown;
	PUCHAR pUnAlignedBuffer = NULL;
	PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex = calloc(1, sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
	CHAR string[NAME_COUNT];
	PCHAR* devicePath = calloc(1, sizeof(PCHAR));
	UINT16 logicalUnitIdentifierLength = 0;
	PUCHAR logicalUnitIdentifier = NULL;
	BOOL configurationPrevented = TRUE;
	PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm = NULL;
	BOOL capTapeEncryption = FALSE;
	BOOL capRfc3447 = FALSE;
	UINT16 wrappedDescriptorsLength = 0;
	PUCHAR wrappedDescriptors = NULL;
	int keyType = -1;
	int keyFormat = -1;
	int keyLength = 0;
	PUCHAR key = NULL;
	BOOL testKey = FALSE;
	BOOL clearKey = FALSE;
	PUCHAR keyAssociatedData = NULL;
	UINT16 keyAssociatedDataStatusLength[2] = { 0 };
	PCHAR keyAssociatedDataStatus[2] = { NULL };
	UINT16 keyAssociatedDataNextBlockLength[2] = { 0 };
	PCHAR keyAssociatedDataNextBlock[2] = { NULL };

	ULONG length = 0,
		errorCode = 0,
		returned = 0;

	if ((argc < 2) || (argc > 4)) {
		printf("---------------------------------------------------\n");
		fprintf(stderr, "Usage:  %s <port-name> [key] [kad]\n\n", argv[0]);
		fprintf(stderr, "Examples:\n");
		fprintf(stderr, "    spti Tape0                    (open the tape class driver in SHARED READ mode)\n");
		fprintf(stderr, "    spti Tape0 D00D00             (Use AES-256 key 0xD00D00 (64 hex digits) on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 D00D00             (Use RSA-2048 wrapped key 0xD00D00 (512 hex digits) on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 D00D00 BackupTape1 (Use RSA-2048 wrapped key 0xD00D00 (512 hex digits) and KAD BackupTape1 on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 weak               (Use a hardcoded really weak test key on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 none               (Disable encryption and decryption on drive Tape0)\n");
		printf("\n---------------------------------------------------\n");

		printf("Enumerating installed tape drives...\n");
		printf("---------------------------------------------------\n");
		HDEVINFO tapeDrives = SetupDiGetClassDevs(&GUID_DEVINTERFACE_TAPE, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
		DWORD deviceIndex = 0;
		PSP_DEVICE_INTERFACE_DATA deviceInterfaceData = calloc(1, sizeof(SP_DEVICE_INTERFACE_DATA));
		deviceInterfaceData->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		PSP_DEVICE_INTERFACE_DETAIL_DATA deviceInterfaceDetailData = NULL;

		while (SetupDiEnumDeviceInterfaces(tapeDrives, NULL, &GUID_DEVINTERFACE_TAPE, deviceIndex, deviceInterfaceData))
		{
			printf("Device Alias: Tape%d\n", deviceIndex);
			// Initialise the SP_DEVICE_INTERFACE_DETAIL_DATA struct
			DWORD bufferSize = 0;
			SetupDiGetDeviceInterfaceDetail(tapeDrives, deviceInterfaceData, NULL, 0, &bufferSize, NULL);
			deviceInterfaceDetailData = calloc(1, bufferSize);
			deviceInterfaceDetailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
			// Populate the SP_DEVICE_INTERFACE_DETAIL_DATA struct
			SetupDiGetDeviceInterfaceDetail(tapeDrives, deviceInterfaceData, deviceInterfaceDetailData, bufferSize, NULL, NULL);
			if (deviceInterfaceDetailData != NULL)
			{
				printf("Device Path: %s\n\n", deviceInterfaceDetailData->DevicePath);
				fileHandle = CreateFile(deviceInterfaceDetailData->DevicePath,
					accessMode,
					shareMode,
					NULL,
					OPEN_EXISTING,
					0,
					NULL);

				if (fileHandle == INVALID_HANDLE_VALUE) {
					errorCode = GetLastError();
					fprintf(stderr, "Error opening %s. Error: %d\n",
						string, errorCode);
					PrintError(errorCode);
				}
				else {
					status = QueryPropertyForDevice(fileHandle, &alignmentMask, &srbType, &storageBusType);
					if (!status) {
						errorCode = GetLastError();
						fprintf(stderr, "Error getting device and/or adapter properties; "
							"error was %d\n", errorCode);
						PrintError(errorCode);
					}
					CloseHandle(fileHandle);
					fileHandle = NULL;
				}

				free(deviceInterfaceDetailData);
				deviceInterfaceDetailData = NULL;
				printf("---------------------------------------------------\n");
			}
			deviceIndex++;
		}
		if (deviceIndex == 0)
		{
			printf("\n** No tape drives found. **\n");
			printf("---------------------------------------------------\n");
		}
		if (fileHandle != NULL)
		{
			CloseHandle(fileHandle);
		}
		if (tapeDrives != NULL)
		{
			SetupDiDestroyDeviceInfoList(tapeDrives);
		}
		return;
	}

	if (strncmp("\\\\", argv[1], 2) == 0)
	{
		*devicePath = argv[1];
	}
	else
	{
		StringCbPrintf(string, sizeof(string), "\\\\.\\%s", argv[1]);
		*devicePath = string;
	}

	if (argc > 2) {
		if (strcmp(argv[2], "weak") == 0) {
			testKey = TRUE;
			keyFormat = SPIN_TAPE_KEY_FORMAT_PLAIN;
		}
		else if (strcmp(argv[2], "none") == 0) {
			clearKey = TRUE;
			keyFormat = SPIN_TAPE_KEY_FORMAT_PLAIN;
		}
		else {
			key = (PUCHAR)argv[2];
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

	if (argc > 3)
	{
		keyAssociatedData = (PUCHAR)argv[3];
	}

	fileHandle = CreateFile(*devicePath,
		accessMode,
		shareMode,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		errorCode = GetLastError();
		fprintf(stderr, "Error opening %s. Error: %d\n",
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
		fprintf(stderr, "Error getting device and/or adapter properties; "
			"error was %d\n", errorCode);
		PrintError(errorCode);
		CloseHandle(fileHandle);
		return;
	}

	printf("** Alignment mask: 0x%08x  **\n\n", alignmentMask);

	printf("** Using %s%s **\n\n", BusTypeStrings[storageBusType], storageBusType == BusTypeSas ? "" : " - only tested with SAS");

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		printf("** Using STORAGE_REQUEST_BLOCK. **\n\n");
	}
	else if (srbType == SRB_TYPE_SCSI_REQUEST_BLOCK)
	{
		printf("** Using SCSI_REQUEST_BLOCK - not currently supported by this program. **\n\n");
	}


	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		int pageCode;

		/*
		* CDB: Inquiry, Device Identifiers VPD page
		*/
		length = ResetSrbIn(psptwb_ex, SCSIOP_INQUIRY);
		if (length == 0) { goto Cleanup; }
		psptwb_ex->spt.Cdb[1] = CDB_INQUIRY_EVPD;
		psptwb_ex->spt.Cdb[2] = VPD_DEVICE_IDENTIFIERS;
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[1];
			if (pageCode == VPD_DEVICE_IDENTIFIERS)
			{
				ParseDeviceIdentifiers((PVPD_IDENTIFICATION_PAGE)psptwb_ex->ucDataBuf, &logicalUnitIdentifierLength, &logicalUnitIdentifier);
			}
		}


		/*
		* CDB: Security Protocol In, Security Protocol Information, Security Compliance page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_INFO, SPIN_SECURITY_COMPLIANCE);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseSecurityCompliance((PSECURITY_PROTOCOL_COMPLIANCE)psptwb_ex->ucDataBuf);
		}


		/*
		* CDB: Security Protocol In, Security Protocol Information, Supported Security Protocol List page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_INFO, SPIN_PROTOCOL_LIST);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseSupportedSecurityProtocolList((PSUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA)psptwb_ex->ucDataBuf, &capTapeEncryption);
			printf("** This device %s Tape Data Encryption. **\n\n", capTapeEncryption ? "supports" : "doesn't support");
			if (!capTapeEncryption)
			{
				goto Cleanup;
			}
		}


		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Management Capabilities page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_MANAGEMENT_CAPABILITIES);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseDataEncryptionManagementCapabilities((PDATA_ENCRYPTION_MANAGEMENT_CAPABILITIES)psptwb_ex->ucDataBuf);
		}


		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Capabilities page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_CAPABILITIES);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_ENCRYPTION_CAPABILITIES)
			{
				ParseDataEncryptionCapabilities((PDATA_ENCRYPTION_CAPABILITIES)psptwb_ex->ucDataBuf, &encryptionAlgorithm, &configurationPrevented);
			}
		}

		if (encryptionAlgorithm != NULL)
		{
			printf("** Algorithm index 0x%02X is the correct algorithm for the current tape. **\n\n", encryptionAlgorithm->AlgorithmIndex);
		}


		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Supported Key Formats page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_SUPPORTED_KEY_FORMATS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_SUPPORTED_KEY_FORMATS)
			{
				ParseSupportedKeyFormats((PSUPPORTED_KEY_FORMATS)psptwb_ex->ucDataBuf, &capRfc3447);
			}
		}

		fprintf(
			capRfc3447 ? stdout : stderr,
			"** This device %s RFC 3447 AES Key-Wrapping. **\n\n", capRfc3447 ? "supports" : "doesn't support"
		);


		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Status page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_STATUS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_ENCRYPTION_STATUS) {
				ParseDataEncryptionStatus((PDATA_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, encryptionAlgorithm, keyAssociatedDataStatusLength, keyAssociatedDataStatus);
			}
		}


		/*
		// CDB: Security Protocol In, Security Protocol Information, Certificate Data
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_INFO, SPIN_CERTIFICATE_DATA);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseCertificateData((PCERTIFICATE_DATA)psptwb_ex->ucDataBuf);
		}


		/*
		* If the device supports AES key wrapping (RFC 3447), try to obtain the public key
		*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Device Server Key Wrapping Public Key page
		*/
		if (capRfc3447 && !configurationPrevented)
		{
			length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_WRAPPED_PUBKEY);
			if (length == 0) { goto Cleanup; }
			status = SendSrb(fileHandle, psptwb_ex, length, &returned);

			if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
			{
				pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
				if (pageCode == SPIN_TAPE_WRAPPED_PUBKEY)
				{
					ParseDeviceServerKeyWrappingPublicKey((PDEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY)psptwb_ex->ucDataBuf, logicalUnitIdentifierLength, logicalUnitIdentifier, &wrappedDescriptorsLength, &wrappedDescriptors);
				}
			}
		}


		/*
		* CDB: Security Protocol Out, Set Data Encryption page
		*/
		if ((key != NULL || testKey || clearKey) && !configurationPrevented)
		{
			printf("Generating Set Data Encryption page...\n");
			if (encryptionAlgorithm == NULL || encryptionAlgorithm->AlgorithmCode != SPIN_TAPE_ALGORITHM_AESGCM)
			{
				fprintf(stderr, "* AES-GCM algorithm index not found.\n");
				goto Cleanup;
			}
			if (keyFormat == SPIN_TAPE_KEY_FORMAT_WRAPPED && !capRfc3447)
			{
				fprintf(stderr, "* Wrapped keys are not supported by the device.\n");
				goto Cleanup;
			}
			if (testKey)
			{
				UINT16 testKeyLength = 32;
				key = calloc(testKeyLength, sizeof(UCHAR));
				if (key != NULL)
				{
					for (int i = 0; i < testKeyLength; i++)
					{
						key[i] = (UCHAR)(i + 0x10);
					}
					keyLength = testKeyLength;
				}
			}

			printf("* AES-GCM algorithm index: 0x%02x\n", encryptionAlgorithm->AlgorithmIndex);

			PUCHAR keyField = NULL;
			UINT16 keyFieldLength = ProcessKey(keyFormat, keyType, keyLength, key, wrappedDescriptorsLength, wrappedDescriptors, &keyField);
			printf("  * Key field length: %u\n", keyFieldLength);

			PPLAIN_KEY_DESCRIPTOR kadField = NULL;
			UINT16 keyAssociatedDataLength = keyAssociatedData == NULL ? 0 : (UINT16)strlen((PCHAR)keyAssociatedData);
			UINT16 kadFieldLength = 0;
			BOOL kadProcessed = ProcessKad(clearKey, keyAssociatedDataLength, keyAssociatedData, encryptionAlgorithm, &kadFieldLength, &kadField);
			if (!kadProcessed) { goto Cleanup; }

			UINT32 allocationLength = FIELD_OFFSET(KEY_HEADER, KeyAndKADList[keyFieldLength + kadFieldLength]);
			length = CreateSecurityProtocolOutSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPOUT_TAPE_SET_DATA_ENCRYPTION);
			if (length == 0) { goto Cleanup; }

			SetDataEncryption(psptwb_ex, allocationLength, (UCHAR)encryptionAlgorithm->AlgorithmIndex, clearKey, (UCHAR)keyFormat, keyFieldLength, keyField, kadFieldLength, kadField);
			printf("* Sending CDB\n");
			status = SendSrb(fileHandle, psptwb_ex, length, &returned);
			printf("* CDB sent\n\n");
			CheckStatus(fileHandle, psptwb_ex, status, returned, length);
		}


		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Status page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_STATUS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_ENCRYPTION_STATUS) {
				ParseDataEncryptionStatus((PDATA_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, encryptionAlgorithm, keyAssociatedDataStatusLength, keyAssociatedDataStatus);
			}
		}


		// CDB: Security Protocol In, Tape Data Encryption Security Protocol, Next Block Encryption Status page
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);
		UCHAR encryptionStatus = 0;

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS) {
				encryptionStatus = ParseNextBlockEncryptionStatus((PNEXT_BLOCK_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, encryptionAlgorithm, keyAssociatedDataNextBlockLength, keyAssociatedDataNextBlock);
			}
		}

		BOOL kadMatches = KeyAuthenticatedDataIsEqual(keyAssociatedDataStatusLength, keyAssociatedDataStatus, keyAssociatedDataNextBlockLength, keyAssociatedDataNextBlock);
		printf("\n** %s KAD %s. **\n", NextBlockEncryptionStatusStrings[encryptionStatus], kadMatches ? "matches" : "doesn't match");
	}

Cleanup:
	if (keyAssociatedDataStatus[0] != NULL) {
		free(keyAssociatedDataStatus[0]);
	}
	if (keyAssociatedDataStatus[1] != NULL) {
		free(keyAssociatedDataStatus[1]);
	}
	if (keyAssociatedDataNextBlock[0] != NULL) {
		free(keyAssociatedDataNextBlock[0]);
	}
	if (keyAssociatedDataNextBlock[1] != NULL) {
		free(keyAssociatedDataNextBlock[1]);
	}
	if (encryptionAlgorithm != NULL) {
		free(encryptionAlgorithm);
	}
	if (pUnAlignedBuffer != NULL) {
		free(pUnAlignedBuffer);
	}
	if (logicalUnitIdentifier != NULL) {
		free(logicalUnitIdentifier);
	}
	if (wrappedDescriptors != NULL) {
		free(wrappedDescriptors);
	}
	if (psptwb_ex != NULL) {
		free(psptwb_ex);
	}
	if (testKey && key != NULL)
	{
		free(key);
	}
	CloseHandle(fileHandle);
	if (devicePath != NULL)
	{
		free(devicePath);
	}
	if (length == 0) {
		fprintf(stderr, "An SRB was not successfully created.");
		return -1;
	}
}

/// <summary>
/// Create a STORAGE_REQUEST_BLOCK for CDB OpCode Security Protocol In
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="securityProtocol">The value for Security Protocol field</param>
/// <param name="pageCode">The value for the Security Protocol Specific field (parameter currently limited to 0x00 to 0xFF)</param>
/// <returns>Length of the SRB in bytes</returns>
ULONG
CreateSecurityProtocolInSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode)
{
	ULONG length = ResetSrbIn(psptwb_ex, SCSIOP_SECURITY_PROTOCOL_IN);
	if (length == 0) { return length; }
	psptwb_ex->spt.Cdb[1] = securityProtocol;
	psptwb_ex->spt.Cdb[2] = (pageCode << 8) & 0xFF00;
	psptwb_ex->spt.Cdb[3] = pageCode & 0xFF;

	return length;
}

/// <summary>
/// Create a STORAGE_REQUEST_BLOCK for CDB OpCode Security Protocol Out
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="securityProtocol">The value for Security Protocol field</param>
/// <param name="pageCode">The value for the Security Protocol Specific field (parameter currently limited to 0x00 to 0xFF)</param>
/// <returns>Length of the SRB in bytes</returns>
ULONG
CreateSecurityProtocolOutSrb(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR securityProtocol, UCHAR pageCode)
{
	ULONG length = ResetSrbOut(psptwb_ex, SCSIOP_SECURITY_PROTOCOL_OUT);
	if (length == 0) { return length; }
	psptwb_ex->spt.Cdb[1] = securityProtocol;
	psptwb_ex->spt.Cdb[2] = (pageCode << 8) & 0xFF00;
	psptwb_ex->spt.Cdb[3] = pageCode & 0xFF;

	return length;
}

/// <summary>
/// Send a STORAGE_REQUEST_BLOCK to a device
/// </summary>
/// <param name="fileHandle">An open handle to the device</param>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="length">Length of the SRB in bytes</param>
/// <param name="returned">A pointer to a ULONG for storing the length of returned data in bytes</param>
/// <returns>0 on failure or pending, non-zero on success</returns>
BOOL
SendSrb(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG length, PULONG returned)
{
	return DeviceIoControl(fileHandle,
		IOCTL_SCSI_PASS_THROUGH_EX,
		psptwb_ex,
		sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX),
		psptwb_ex,
		length,
		returned,
		FALSE);
}

/// <summary>
/// Prints a hexdump of returned data (or error data) for an SRB (direction: in/read)
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="status">Status returned from DeviceIoControl</param>
/// <param name="length">Length of the SRB in bytes</param>
/// <param name="returned">Length of returned data in bytes</param>
/// <param name="cdbDescription">A description string used as a title in the output</param>
VOID
ParseSimpleSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, ULONG status, ULONG length, DWORD returned, PCHAR cdbDescription)
{
	printf("%s:\n\n", cdbDescription);
	PrintDataBuffer(psptwb_ex->ucDataBuf, psptwb_ex->spt.DataInTransferLength);

	if (!status || psptwb_ex->spt.ScsiStatus != SCSISTAT_GOOD)
	{
		printf("Status: 0x%02X\n", psptwb_ex->spt.ScsiStatus);
		PrintStatusResultsEx(status, returned, psptwb_ex, length);
	}
}

/// <summary>
/// Parses a pointer to a SECURITY_PROTOCOL_COMPLIANCE struct
/// </summary>
/// <param name="pSecurityCompliance">A pointer to a SECURITY_PROTOCOL_COMPLIANCE struct</param>
VOID
ParseSecurityCompliance(PSECURITY_PROTOCOL_COMPLIANCE pSecurityCompliance)
{
	printf("Parsing Security Compliance page...\n");
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	pSecurityCompliance->PageLength = ntohl(pSecurityCompliance->PageLength);

	UINT32 currentDescriptorTotalLength = 0;
	for (UINT32 i = 0; i < pSecurityCompliance->PageLength; i += currentDescriptorTotalLength)
	{
		// Descriptors are in the Descriptor field. i is the byte offset of the current descriptor in that field.
		PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR currentDescriptor = (PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR)(pSecurityCompliance->Descriptor + i);
		// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
		currentDescriptor->DescriptorType = ntohs(currentDescriptor->DescriptorType);
		currentDescriptor->DescriptorLength = ntohl(currentDescriptor->DescriptorLength);
		// The number of bytes from i to the last byte of the current descriptor
		currentDescriptorTotalLength = FIELD_OFFSET(SECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR, DescriptorInformation[currentDescriptor->DescriptorLength]);
		PCHAR description;
		switch (currentDescriptor->DescriptorType)
		{
		case SPIN_SECURITY_COMPLIANCE_FIPS140:
			description = "Security requirements for cryptographic modules";
			break;
		default:
			description = "Unknown";
			break;
		}
		printf("* Descriptor Type: 0x%04x (%s)\n", currentDescriptor->DescriptorType, description);
		if (currentDescriptor->DescriptorType == SPIN_SECURITY_COMPLIANCE_FIPS140) {
			PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR_INFO_FIPS140 descriptorInfo = (PSECURITY_PROTOCOL_COMPLIANCE_DESCRIPTOR_INFO_FIPS140)(currentDescriptor->DescriptorInformation);
			// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
			currentDescriptor->DescriptorType = ntohs(currentDescriptor->DescriptorType);
			currentDescriptor->DescriptorLength = ntohl(currentDescriptor->DescriptorLength);
			switch (descriptorInfo->Revision) {
			case SPIN_SECURITY_COMPLIANCE_FIPS140_2:
				description = "FIPS 140-2";
				break;
			case SPIN_SECURITY_COMPLIANCE_FIPS140_3:
				description = "FIPS 140-3";
				break;
			default:
				description = "Unknown";
			}
			printf("  * Revision: %s\n", description);
			printf("  * Overall Security Level: %c\n", descriptorInfo->OverallSecurityLevel);
			PCHAR hardwareVersion = NullPaddedNullTerminatedToString(sizeof(descriptorInfo->HardwareVersion), descriptorInfo->HardwareVersion);
			if (hardwareVersion != NULL) {
				printf("  * Hardware Level: %s\n", hardwareVersion);
				free(hardwareVersion);
			}
			PCHAR softwareVersion = NullPaddedNullTerminatedToString(sizeof(descriptorInfo->SoftwareVersion), descriptorInfo->SoftwareVersion);
			if (softwareVersion != NULL) {
				printf("  * Software Level: %s\n", softwareVersion);
				free(softwareVersion);
			}
			PCHAR moduleName = NullPaddedNullTerminatedToString(sizeof(descriptorInfo->ModuleName), descriptorInfo->ModuleName);
			if (moduleName != NULL) {
				printf("  * Module Name: %s\n", moduleName);
				free(moduleName);
			}
		}
	}
	printf("\n");
}

/// <summary>
/// Convert a null-padded, null-terminated string into a null-terminated string
/// </summary>
/// <param name="arrayLength">Length of character array</param>
/// <param name="characterArray">A character array</param>
/// <returns>A null-terminated string, or NULL</returns>
PCHAR
NullPaddedNullTerminatedToString(UINT32 arrayLength, PUCHAR characterArray)
{
	// Assume that null terminated strings don't need an extra byte for NUL
	PCHAR newArray = calloc(arrayLength, sizeof(CHAR));
	if (newArray == NULL) { return NULL; }
	BOOL endOfLeadingZeroes = FALSE;
	CHAR currentChar;
	UINT32 nextChar = 0;
	for (UINT32 i = 0; i < arrayLength; i++)
	{
		currentChar = characterArray[i];
		// Assume leading zero bytes are padding
		if (currentChar == 0 && !endOfLeadingZeroes) {
			continue;
		}
		// If a non-zero byte has occurred and this byte is zero, assume null termination character
		else if (currentChar == 0 && endOfLeadingZeroes) {
			return newArray;
		}
		// If byte is non-zero, assume it is part of the string
		else if (currentChar != 0) {
			newArray[nextChar] = currentChar;
			nextChar++;
			if (!endOfLeadingZeroes) {
				endOfLeadingZeroes = TRUE;
			}
		}
	}
	return NULL;
}

/// <summary>
/// Parse a pointer to a SUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA struct
/// </summary>
/// <param name="securityProtocolList">Pointer to a SUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA struct</param>
/// <param name="pCapTapeEncryption">Pointer to a boolean to store Tape Encryption support</param>
VOID
ParseSupportedSecurityProtocolList(PSUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA securityProtocolList, PBOOL pCapTapeEncryption)
{
	printf("Parsing Supported Security Protocol List page...\n");
	// Unset existing tape encryption capability value
	*pCapTapeEncryption = FALSE;
	int listCount = securityProtocolList->SupportedSecurityListLength[0] << 8 | securityProtocolList->SupportedSecurityListLength[1];
	for (int i = 0; i < listCount; i++)
	{
		if (securityProtocolList->SupportedSecurityProtocol[i] == SECURITY_PROTOCOL_TAPE) {
			*pCapTapeEncryption = TRUE;
		}
		printf("* Supported Security Protocol: 0x%02X (%s)\n",
			securityProtocolList->SupportedSecurityProtocol[i],
			GetSecurityProtocolDescription(securityProtocolList->SupportedSecurityProtocol[i])
		);
	}
	printf("\n");
}

/// <summary>
/// Parse a pointer to a DATA_ENCRYPTION_MANAGEMENT_CAPABILITIES struct
/// </summary>
/// <param name="encryptionManagementCapabilities">A DATA_ENCRYPTION_MANAGEMENT_CAPABILITIES struct</param>
VOID
ParseDataEncryptionManagementCapabilities(PDATA_ENCRYPTION_MANAGEMENT_CAPABILITIES encryptionManagementCapabilities)
{
	printf("Parsing Data Encryption Management Capabilities page...\n");
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	encryptionManagementCapabilities->PageCode = ntohs(encryptionManagementCapabilities->PageCode);
	encryptionManagementCapabilities->PageLength = ntohs(encryptionManagementCapabilities->PageLength);
	printf("* Lock Capable (LOCK_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->LockCapable));
	printf("* Clear Key On Reservation Loss Capable (CKORL_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->ClearKeyOnReservationLossCapable));
	printf("* Clear Key On Reservation Pre-empted Capable (CKORP_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->ClearKeyOnReservationPreemptedCapable));
	printf("* Clear Key On Demount Capable (CKOD_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->ClearKeyOnDemountCapable));
	printf("* Public scope Capable (Public_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->PublicScopeCapable));
	printf("* Local scope Capable (Local_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->LocalScopeCapable));
	printf("* All I_T Nexus scope Capable (AITN_C): %s\n", BOOLEAN_TO_STRING(encryptionManagementCapabilities->AITNScopeCapable));
	printf("\n");
}

/// <summary>
/// Parse a pointer to a DATA_ENCRYPTION_CAPABILITIES struct
/// </summary>
/// <param name="pBuffer">A pointer to a DATA_ENCRYPTION_CAPABILITIES struct</param>
/// <param name="ppDataEncryptionAlgorithm">A pointer to a pointer to a DATA_ENCRYPTION_ALGORITHM struct for storing the selected encryption algorithm</param>
/// <param name="configurationPrevented">A pointer to a BOOL for storing whether data encryption configuration is disabled</param>
VOID
ParseDataEncryptionCapabilities(PDATA_ENCRYPTION_CAPABILITIES pBuffer, PDATA_ENCRYPTION_ALGORITHM* ppDataEncryptionAlgorithm, PBOOL configurationPrevented)
{
	printf("Parsing Data Encryption Capabilities page...\n");
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	pBuffer->PageCode = ntohs(pBuffer->PageCode);
	pBuffer->PageLength = ntohs(pBuffer->PageLength);
	printf("Page length: %d bytes\n", pBuffer->PageLength);
	printf("* External Data Encryption Capable (EXTDECC): %s\n", BOOLEAN_TO_STRING(pBuffer->ExternalDataEncryptionCapable == 0b10));
	*configurationPrevented = pBuffer->ConfigurationPrevented == 0x10;
	printf("* Configuration Prevented (CFG_P): %s\n", CfgPCapableStrings[pBuffer->ConfigurationPrevented]);
	UINT16 totalPageLength = 4 + pBuffer->PageLength;
	UINT16 firstAlgorithmOffset = (UINT16)offsetof(DATA_ENCRYPTION_CAPABILITIES, AlgorithmList[0]);
	UINT16 algorithmListLength = totalPageLength - firstAlgorithmOffset;
	UINT16 algorithmIndexCount = algorithmListLength / (UINT16)sizeof(DATA_ENCRYPTION_ALGORITHM);
	printf("* Algorithm count: %d\n", algorithmIndexCount);
	for (UINT16 i = 0; i < algorithmIndexCount; i++)
	{
		PDATA_ENCRYPTION_ALGORITHM currentAlgorithm = &pBuffer->AlgorithmList[i];
		// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
		currentAlgorithm->DescriptorLength = ntohs(currentAlgorithm->DescriptorLength);
		currentAlgorithm->UnauthKadMaxLength = ntohs(currentAlgorithm->UnauthKadMaxLength);
		currentAlgorithm->AuthKadMaxLength = ntohs(currentAlgorithm->AuthKadMaxLength);
		currentAlgorithm->KeySize = ntohs(currentAlgorithm->KeySize);
		currentAlgorithm->MaximumSupplementalDecryptionKeyCount = ntohs(currentAlgorithm->MaximumSupplementalDecryptionKeyCount);
		currentAlgorithm->AlgorithmCode = ntohl(currentAlgorithm->AlgorithmCode);
		printf("  * Algorithm index: 0x%02X\n", currentAlgorithm->AlgorithmIndex);
		printf("    * Descriptor Length: %d bytes\n", currentAlgorithm->DescriptorLength);
		printf("    * Algorithm Valid For Mounted Volume (AVFMV): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->AlgorithmValidForMountedVolume));
		printf("    * Supplemental Decryption Key Capable (SDK_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->SupplementalDecryptionKeyCapable));
		printf("    * Message Authentication Code Capable (MAC_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->MacKadCapable));
		printf("    * Distinguish Encrypted Logical Block Capable (DELB_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->DistinguishEncryptedLogicalBlockCapable));
		printf("    * Decryption Capable (Decrypt_C): %s\n", EncryptionCapableStrings[currentAlgorithm->DecryptCapable]);
		printf("    * Encryption Capable (Encrypt_C): %s\n", EncryptionCapableStrings[currentAlgorithm->EncryptCapable]);
		printf("    * Algorithm Valid For Current Logical Position (AVFCLP): %s\n", AvfclpCapableStrings[currentAlgorithm->AlgorithmValidForCurrentLogicalPosition]);
		printf("    * Nonce value descriptor capable (NONCE_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->NonceKadCapable == 0b11));
		printf("    * KAD Format Capable (KADF_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->KadFormatCapable));
		printf("    * Volume Contains Encrypted Logical Blocks Capable (VCELB_C): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->VolumeContainsEncryptedLogicalBlocksCapable));
		printf("    * Unauthenticated KAD Fixed Length (UKADF): %s\n", (currentAlgorithm->UnauthKadFixedLength ? "Max UKAD Bytes" : "1 Byte to Max UKAD Bytes"));
		printf("    * Authenticated KAD Fixed Length (AKADF): %s\n", (currentAlgorithm->AuthKadFixedLength ? "Max AKAD Bytes" : "1 Byte to Max AKAD Bytes"));
		printf("    * Maximum Unauthenticated Key-Associated Data Bytes: %d\n", currentAlgorithm->UnauthKadMaxLength);
		printf("    * Maximum Authenticated Key-Associated Data Bytes: %d\n", currentAlgorithm->AuthKadMaxLength);
		printf("    * Key Size: %d bytes (%d-bit)\n", currentAlgorithm->KeySize, currentAlgorithm->KeySize * 8);
		printf("    * Decryption KAD Capability: %s\n", DkadCapableStrings[currentAlgorithm->DecryptionKadCapable]);
		printf("    * External Encryption Mode Control Capable (EEMC_C): %s\n", EemcCapableStrings[currentAlgorithm->ExternalEncryptionModeControlCapable]);
		if (currentAlgorithm->RawDecryptionModeControlCapabilities == 0x4)
		{
			printf("    * Raw Decryption Mode Control (RDMC_C): Raw decryption not allowed by default\n");
		}
		else
		{
			printf("    * Raw Decryption Mode Control (RDMC_C): 0x%02X\n", currentAlgorithm->RawDecryptionModeControlCapabilities);
		}
		printf("    * Encryption Algorithm Records Encryption Mode (EAREM): %s\n", BOOLEAN_TO_STRING(currentAlgorithm->EncryptionAlgorithmRecordsEncryptionMode));
		printf("    * Maximum number of supplemental decryption keys: %d\n", currentAlgorithm->MaximumSupplementalDecryptionKeyCount);
		if (currentAlgorithm->AlgorithmCode == SPIN_TAPE_ALGORITHM_AESGCM)
		{
			printf("    * Algorithm: AES-GCM (AES%d-GCM)\n", currentAlgorithm->KeySize * 8);
			// Algorithm is AES256-GCM and is valid for the current tape - it is the one to be used
			if (currentAlgorithm->AlgorithmValidForMountedVolume)
			{
				// Allocate memory to store encryption algorithm
				PDATA_ENCRYPTION_ALGORITHM selectedAlgorithm = calloc(1, sizeof(DATA_ENCRYPTION_ALGORITHM));
				// Update pointer to new struct
				*ppDataEncryptionAlgorithm = selectedAlgorithm;
				// Copy correct algorithm to struct
				memcpy(selectedAlgorithm, currentAlgorithm, sizeof(DATA_ENCRYPTION_ALGORITHM));
			}
		}
		else
		{
			printf("    * Unknown Algorithm: 0x%08X\n", currentAlgorithm->AlgorithmCode);
		}
	}
	printf("\n");
}

/// <summary>
/// Parse a pointer to a DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY struct
/// </summary>
/// <param name="deviceServerKeyWrappingPublicKey">A pointer to a DEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY struct</param>
/// <param name="logicalUnitIdentifierLength">The length of the logical unit identifier</param>
/// <param name="logicalUnitIdentifier">A pointer to a character array containing the logical unit identifier</param>
/// <param name="wrappedDescriptorsLength">A pointer to an int that will contain the length of the wrapped descriptors</param>
/// <param name="wrappedDescriptorsPtr">A pointer to a character array that will point to a character array containing the wrapped descriptors</param>
/// <returns>FALSE if there was a problem with the public key, otherwise TRUE</returns>
BOOL
ParseDeviceServerKeyWrappingPublicKey(PDEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY deviceServerKeyWrappingPublicKey, UINT16 logicalUnitIdentifierLength, PUCHAR logicalUnitIdentifier, PUINT16 wrappedDescriptorsLength, PUCHAR* wrappedDescriptorsPtr)
{
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	deviceServerKeyWrappingPublicKey->PageCode = ntohs(deviceServerKeyWrappingPublicKey->PageCode);
	deviceServerKeyWrappingPublicKey->PageLength = ntohs(deviceServerKeyWrappingPublicKey->PageLength);
	deviceServerKeyWrappingPublicKey->PublicKeyType = ntohl(deviceServerKeyWrappingPublicKey->PublicKeyType);
	deviceServerKeyWrappingPublicKey->PublicKeyFormat = ntohl(deviceServerKeyWrappingPublicKey->PublicKeyFormat);
	deviceServerKeyWrappingPublicKey->PublicKeyLength = ntohs(deviceServerKeyWrappingPublicKey->PublicKeyLength);

	printf("Parsing Device Server Key Wrapping Public Key page...\n");
	printf("Page length: %d bytes\n", deviceServerKeyWrappingPublicKey->PageLength);
	PRSA2048_PUBLIC_KEY rsa2048PublicKey = NULL;
	int modulusLength = 0;
	int modulusOffset = 0;
	int exponentLength = 0;
	int exponentOffset = 0;
	PCHAR description;
	BOOL keyFormatConsistent = FALSE;
	BOOL keyLengthConsistent = FALSE;
	// Analyse the key metadata for consistency
	switch (deviceServerKeyWrappingPublicKey->PublicKeyType) {
	case SPIN_TAPE_PUBKEY_TYPE_RSA2048:
		description = "RSA-2048";
		keyFormatConsistent = deviceServerKeyWrappingPublicKey->PublicKeyFormat == SPIN_TAPE_PUBKEY_FORMAT_RSA2048;
		keyLengthConsistent = deviceServerKeyWrappingPublicKey->PublicKeyLength == SPIN_TAPE_PUBKEY_LENGTH_RSA2048;
		modulusLength = SPIN_TAPE_PUBKEY_LENGTH_RSA2048 / 2; // 256 bytes for RSA-2048
		exponentLength = SPIN_TAPE_PUBKEY_LENGTH_RSA2048 / 2; // 256 bytes for RSA-2048
		break;
	case SPIN_TAPE_PUBKEY_TYPE_ECC521:
		description = "ECC-521";
		keyFormatConsistent = deviceServerKeyWrappingPublicKey->PublicKeyFormat == SPIN_TAPE_PUBKEY_FORMAT_ECC521;
		keyLengthConsistent = deviceServerKeyWrappingPublicKey->PublicKeyLength == SPIN_TAPE_PUBKEY_LENGTH_ECC521;
		// TODO: Work out how X9.63 stores ECC keys and how to calculate length parameters
		break;
	default:
		description = "Unknown";
		break;
	}
	// Return early if key format is inconsistent with key type
	if (!keyFormatConsistent)
	{
		fprintf(stderr, "\nPublic Key type %s and key format 0x%08x are not consistent.\n", description, deviceServerKeyWrappingPublicKey->PublicKeyFormat);
		return FALSE;
	}
	// Return early if key length is inconsistent with key type
	if (!keyLengthConsistent)
	{
		fprintf(stderr, "\nPublic Key type %s and wrapped key length (%d bytes) are not consistent.\n", description, deviceServerKeyWrappingPublicKey->PublicKeyLength);
		return FALSE;
	}
	printf("* Public Key Type: %s\n", description);
	// If the key type is handled, cast the PublicKey field to a key type specific struct
	if (deviceServerKeyWrappingPublicKey->PublicKeyType == SPIN_TAPE_PUBKEY_TYPE_RSA2048) {
		rsa2048PublicKey = (PRSA2048_PUBLIC_KEY)deviceServerKeyWrappingPublicKey->PublicKey;
	}
	// If RSA-2048, find the first (most significant) non-zero byte for the modulus and exponent
	if (rsa2048PublicKey != NULL) {
		for (int i = 0; i < modulusLength; i++)
		{
			if (rsa2048PublicKey->Modulus[i] == 0)
			{
				modulusOffset++;
				continue;
			}
			else
			{
				break;
			}
		}
		for (int i = 0; i < exponentLength; i++)
		{
			if (rsa2048PublicKey->Exponent[i] == 0)
			{
				exponentOffset++;
				continue;
			}
			else
			{
				break;
			}
		}
	}
	// Convert the public key to hex-encoded DER if the following are true:
	// 1) The modulus is 256 bytes (2048-bit),
	// 2) The exponent is 3 bytes long (99.5% of RSA keys use e=65537=0x010001)
	// NB: A 2040-bit (255 byte) modulus fails to meet these conditions - DER forbids integers starting 0x0000
	if (rsa2048PublicKey != NULL && modulusOffset == 0 && exponentOffset == (exponentLength - 3))
	{
		// ASN.1
		printf("  * DER: 30820122"); // 30=SEQUENCE, 82=multibyte length (0x80) using 2 bytes (0x2), 0122=length
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
			printf("%X", (rsa2048PublicKey->Modulus[i] & 0xFF) >> 4); // Upper 4 bits
			printf("%X", rsa2048PublicKey->Modulus[i] & 0x0F); // Lower 4 bits
		}
		// Exponent integer
		printf("02%02X", 256 - exponentOffset); // 02=INTEGER, %02X=length
		for (int i = exponentOffset; i < 256; i++)
		{
			printf("%X", (rsa2048PublicKey->Exponent[i] & 0xFF) >> 4); // Upper 4 bits
			printf("%X", rsa2048PublicKey->Exponent[i] & 0x0F); // Lower 4 bits
		}
		printf("\n");

		// The length for a wrapped key descriptor containing the logical unit identifier
		int deviceServerIdentificationLength = FIELD_OFFSET(WRAPPED_KEY_DESCRIPTOR, Descriptor[logicalUnitIdentifierLength]);
		// The number 256 requires 2 bytes of storage
		UINT16 wrappedKeyLengthLength = 2;
		// The length for a wrapped key descriptor containing the number 256
		int wrappedKeyLengthDescriptorLength = FIELD_OFFSET(WRAPPED_KEY_DESCRIPTOR, Descriptor[wrappedKeyLengthLength]);
		// The combined length of all wrapped key descriptors
		*wrappedDescriptorsLength = (UINT16)(deviceServerIdentificationLength + wrappedKeyLengthDescriptorLength);
		// Allocate memory to store the combined descriptors
		PUCHAR wrappedDescriptors = calloc(*wrappedDescriptorsLength, 1);
		// Update the pointer outside the function
		*wrappedDescriptorsPtr = wrappedDescriptors;

		// Create a wrapped key descriptor at byte 0 for the device server identification descriptor
		PWRAPPED_KEY_DESCRIPTOR deviceServerIdentification = (PWRAPPED_KEY_DESCRIPTOR)(wrappedDescriptors + 0);
		deviceServerIdentification->Type = WRAPPED_KEY_DESCRIPTOR_TYPE_DEVICE_ID;
		deviceServerIdentification->Length = htons(logicalUnitIdentifierLength);
		memcpy(deviceServerIdentification->Descriptor, logicalUnitIdentifier, logicalUnitIdentifierLength);

		// Append a wrapped key descriptor for the wrapped key length descriptor
		PWRAPPED_KEY_DESCRIPTOR wrappedKeyLengthDescriptor = (PWRAPPED_KEY_DESCRIPTOR)(wrappedDescriptors + deviceServerIdentificationLength);
		wrappedKeyLengthDescriptor->Type = WRAPPED_KEY_DESCRIPTOR_TYPE_KEY_LENGTH;
		wrappedKeyLengthDescriptor->Length = htons(wrappedKeyLengthLength);
		wrappedKeyLengthDescriptor->Descriptor[0] = 0x01; // MSB of 256 (0x0100)
		wrappedKeyLengthDescriptor->Descriptor[1] = 0x00; // LSB of 256 (0x0100)

		printf("* Wrapped Key Descriptors: ");
		for (int i = 0; i < *wrappedDescriptorsLength; i++)
		{
			printf("%X", (wrappedDescriptors[i] & 0xFF) >> 4); // Upper 4 bits
			printf("%X", wrappedDescriptors[i] & 0x0F); // Lower 4 bits
		}
		printf("\n\n");
	}
	else
	{
		fprintf(stderr, "\nOnly RSA-2048 public keys with a 256 byte modulus and 3 byte exponent are currently supported.\n");
	}
	return TRUE;
}

/// <summary>
/// Parse a pointer to a VPD_IDENTIFICATION_PAGE struct
/// </summary>
/// <param name="deviceIdentifiers">A pointer to a VPD_IDENTIFICATION_PAGE struct</param>
/// <param name="pLogicalUnitIdentifierLength">A pointer to an int that will contain the length of the logical unit identifier</param>
/// <param name="ppLogicalUnitIdentifier">A pointer to a character array that will point to a character array containing the logical unit identifier</param>
VOID
ParseDeviceIdentifiers(PVPD_IDENTIFICATION_PAGE deviceIdentifiers, PUINT16 pLogicalUnitIdentifierLength, PUCHAR* ppLogicalUnitIdentifier)
{
	printf("Parsing Device Identifiers page...\n");
	int identifierTotalLength = 0;
	int currentIdentifier = 0;
	PVPD_IDENTIFICATION_DESCRIPTOR identifier = NULL;
	PCHAR description = NULL;
	int identifierInt = 0;
	for (int i = 0; i < deviceIdentifiers->PageLength; i += identifierTotalLength)
	{
		identifier = (PVPD_IDENTIFICATION_DESCRIPTOR)(deviceIdentifiers->Descriptors + i);
		identifierTotalLength = FIELD_OFFSET(VPD_IDENTIFICATION_DESCRIPTOR, Identifier[identifier->IdentifierLength]);
		switch (identifier->Association)
		{
		case VpdAssocDevice:
			description = "Logical Unit Identifier";
			break;
		case VpdAssocPort:
			description = "Port Identifier";
			break;
		case VpdAssocTarget:
			description = "Target Device Identifier";
			break;
		default:
			description = "Unknown Association";
			break;
		}
		switch (identifier->IdentifierType)
		{
		case VpdIdentifierTypeVendorId:
			printf("* Vendor ID (%s): ", description);
			if (identifier->CodeSet == VpdCodeSetAscii) {
				PCHAR vendorId = calloc((size_t)identifier->IdentifierLength + 1, sizeof(UCHAR));
				if (vendorId != NULL)
				{
					strncpy_s(vendorId, (size_t)identifier->IdentifierLength + 1, (PCHAR)identifier->Identifier, identifier->IdentifierLength);
					printf("%s\n", vendorId);
					free(vendorId);
				}
			}
			else {
				PrintDataBuffer(identifier->Identifier, identifier->IdentifierLength);
			}
			break;
		case VpdIdentifierTypeFCPHName:
			printf("* IEEE WWN (%s): ", description);
			if (identifier->CodeSet == VpdCodeSetBinary) {
				for (int j = 0; j < identifier->IdentifierLength; j++)
				{
					if (j > 0) { printf(":"); }
					printf("%X", (identifier->Identifier[j] & 0xFF) >> 4); // Upper 4 bits
					printf("%X", identifier->Identifier[j] & 0x0F); // Lower 4 bits
				}
				printf("\n");
			}
			else {
				printf("\n");
				PrintDataBuffer(identifier->Identifier, identifier->IdentifierLength);
			}
			break;
		case VpdIdentifierTypePortRelative:
			if (identifier->CodeSet == VpdCodeSetBinary) {
				identifierInt = identifier->Identifier[0] << 24 | identifier->Identifier[1] << 16 | identifier->Identifier[2] << 8 | identifier->Identifier[3];
				printf("* Relative Port Identifier: %d\n", identifierInt);
			}
			break;
		case VpdIdentifierTypeTargetPortGroup:
			if (identifier->CodeSet == VpdCodeSetBinary) {
				identifierInt = identifier->Identifier[0] << 24 | identifier->Identifier[1] << 16 | identifier->Identifier[2] << 8 | identifier->Identifier[3];
				printf("* Target Port Group Identifier: %d\n", identifierInt);
			}
			break;
		default:
			printf("* Other identifier (%s):...\n", description);
			PrintDataBuffer(identifier->Identifier, identifier->IdentifierLength);
		}
		if ((identifier->Reserved2 >> 1) != 0x0) {
			if ((identifier->Association == VpdAssocPort || identifier->Association == VpdAssocTarget) && (identifier->Reserved2 >> 1) == 0x1) {
				switch (identifier->Reserved) {
				case 0x0:
					description = "Fibre Channel";
					break;
				case 0x2:
					description = "SSA";
					break;
				case 0x3:
					description = "IEEE 1394";
					break;
				case 0x4:
					description = "RDMA";
					break;
				case 0x5:
					description = "iSCSI";
					break;
				case 0x6:
					description = "Serial Attached SCSI (SAS)";
					break;
				default:
					description = "Unknown protocol";
					break;
				}
				printf("   via %s (0x%01X)\n", description, identifier->Reserved);
			}
		}
		if (currentIdentifier == 0) {
			*pLogicalUnitIdentifierLength = identifier->IdentifierLength;
			PUCHAR logicalUnitIdentifier = calloc(identifier->IdentifierLength, sizeof(UCHAR));
			if (logicalUnitIdentifier != NULL)
			{
				*ppLogicalUnitIdentifier = logicalUnitIdentifier;
				memcpy(logicalUnitIdentifier, identifier->Identifier, identifier->IdentifierLength);
			}
		}
		currentIdentifier++;
	}
	printf("\n");
}

/// <summary>
/// Parse a pointer to a SUPPORTED_KEY_FORMATS struct
/// </summary>
/// <param name="supportedKeyFormats">A pointer to a SUPPORTED_KEY_FORMATS struct</param>
/// <param name="pCapRfc3447">A pointer to a boolean for holding RFC 3447 capability</param>
VOID
ParseSupportedKeyFormats(PSUPPORTED_KEY_FORMATS supportedKeyFormats, PBOOL pCapRfc3447)
{
	printf("Parsing Supported Key Formats page...\n");
	*pCapRfc3447 = FALSE;
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	supportedKeyFormats->PageCode = ntohs(supportedKeyFormats->PageCode);
	supportedKeyFormats->PageLength = ntohs(supportedKeyFormats->PageLength);

	PCHAR description;
	for (int i = 0; i < supportedKeyFormats->PageLength; i++)
	{
		switch (supportedKeyFormats->KeyFormats[i])
		{
		case SPIN_TAPE_KEY_FORMAT_PLAIN:
			description = "Plain-text";
			break;
		case SPIN_TAPE_KEY_FORMAT_WRAPPED:
			description = "Wrapped/RFC 3447";
			*pCapRfc3447 = TRUE;
			break;
		default:
			description = "Unknown";
			break;
		}
		printf("* Supported Key Format: 0x%02X (%s)\n", supportedKeyFormats->KeyFormats[i], description);
	}
	printf("\n");
}

/// <summary>
/// Parse a pointer to a DATA_ENCRYPTION_STATUS struct
/// </summary>
/// <param name="dataEncryptionStatus">A pointer to a DATA_ENCRYPTION_STATUS struct</param>
/// <param name="encryptionAlgorithm">The drive's encryption algorithm for AES256-GCM</param>
/// <param name="keyAssociatedDataStatusLength">A pointer for storing an array of KAD lengths</param>
/// <param name="keyAssociatedDataStatus">A pointer for storing an array of KAD character arrays</param>
VOID
ParseDataEncryptionStatus(PDATA_ENCRYPTION_STATUS dataEncryptionStatus, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 keyAssociatedDataStatusLength, PCHAR* keyAssociatedDataStatus)
{
	printf("Parsing Data Encryption Status page...\n");
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	dataEncryptionStatus->PageCode = ntohs(dataEncryptionStatus->PageCode);
	dataEncryptionStatus->PageLength = ntohs(dataEncryptionStatus->PageLength);
	dataEncryptionStatus->KeyInstanceCounter = ntohl(dataEncryptionStatus->KeyInstanceCounter);
	dataEncryptionStatus->AvailableSupplementalDecryptionKeys = ntohs(dataEncryptionStatus->AvailableSupplementalDecryptionKeys);
	printf("* Key Scope: %s (0x%01x)\n", EncryptionParametersScopeStrings[dataEncryptionStatus->KeyScope], dataEncryptionStatus->KeyScope);
	printf("* I_T Nexus Scope: %s (0x%01x)\n", EncryptionParametersScopeStrings[dataEncryptionStatus->KeyScope], dataEncryptionStatus->ItNexusScope);
	printf("* Encryption Mode: %s\n", EncryptionModeStrings[dataEncryptionStatus->EncryptionMode]);
	printf("* Decryption Mode: %s\n", DecryptionModeStrings[dataEncryptionStatus->DecryptionMode]);
	printf("* Algorithm Index: 0x%02x (%s)\n", dataEncryptionStatus->AlgorithmIndex, encryptionAlgorithm != NULL && dataEncryptionStatus->AlgorithmIndex == encryptionAlgorithm->AlgorithmIndex ? "AES256-GCM" : "Unknown");
	printf("* Key Instance Counter: %d\n", dataEncryptionStatus->KeyInstanceCounter);
	printf("* Raw Decryption Mode Disabled (RDMD): %s\n", BOOLEAN_TO_STRING(dataEncryptionStatus->RawDecryptionModeDisabled));
	printf("* Check External Encryption Mode Status (CEEMS): 0x%01x\n", dataEncryptionStatus->CheckExternalEncryptionModeStatus);
	printf("* Volume Contains Encrypted Logical Blocks (VCELB): %s\n", BOOLEAN_TO_STRING(dataEncryptionStatus->VolumeContainsEncryptedLogicalBlocks));
	printf("* Parameters Control: %s\n", EncryptionParametersControlStings[dataEncryptionStatus->ParametersControl]);
	printf("* Encryption Parameters KAD Format: %s (0x%02X)\n",
		dataEncryptionStatus->EncryptionParametersKadFormat < NUMBER_OF_KAD_FORMAT_STRINGS
		? KadFormatStrings[dataEncryptionStatus->EncryptionParametersKadFormat]
		: KadFormatStrings[NUMBER_OF_KAD_FORMAT_STRINGS - 1],
		dataEncryptionStatus->EncryptionParametersKadFormat
	);
	printf("* Available Supplemental Decryption Key Count (ASDKC): %d\n", dataEncryptionStatus->AvailableSupplementalDecryptionKeys);
	int kadListLength = (UINT16)dataEncryptionStatus->PageLength - 20;
	printf("* KAD List Length: 0x%02x (%d bytes)\n", kadListLength, kadListLength);
	for (int i = 0; i < 2; i++)
	{
		if (keyAssociatedDataStatus[i] != NULL)
		{
			keyAssociatedDataStatusLength[i] = 0;
			free(keyAssociatedDataStatus[i]);
			keyAssociatedDataStatus[i] = NULL;
		}
	}
	PPLAIN_KEY_DESCRIPTOR kad = NULL;
	int currentKadTotalLength = 0;
	for (int i = 0; i < kadListLength; i += currentKadTotalLength)
	{
		UINT16 currentKadLength = dataEncryptionStatus->KADList[i + 2] << 8 | dataEncryptionStatus->KADList[i + 3];
		currentKadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[currentKadLength]);
		kad = calloc(currentKadTotalLength, 1);
		if (kad != NULL)
		{
			memcpy(kad, dataEncryptionStatus->KADList + i, currentKadTotalLength);
			printf("  * KAD Type: 0x%02x\n", kad->Type);
			printf("    * KAD Length: %d\n", currentKadLength);
			if (dataEncryptionStatus->EncryptionParametersKadFormat == SPOUT_TAPE_KAD_FORMAT_ASCII)
			{
				printf("    * KAD: %.*s\n", currentKadLength, kad->Descriptor);
				if (kad->Type < SPOUT_TAPE_KAD_PLAIN_TYPE_NONCE)
				{
					keyAssociatedDataStatus[kad->Type] = calloc(currentKadLength, sizeof(UCHAR));
					if (keyAssociatedDataStatus[kad->Type] != NULL)
					{
						memcpy(keyAssociatedDataStatus[kad->Type], kad->Descriptor, currentKadLength);
						keyAssociatedDataStatusLength[kad->Type] = currentKadLength;
					}
				}
			}
			else
			{
				fprintf(stderr, "Currently only able to display ASCII KADs.\n");
			}
			free(kad);
		}
	}
	printf("\n");
}

/// <summary>
/// Parse a pointer to a NEXT_BLOCK_ENCRYPTION_STATUS struct
/// </summary>
/// <param name="nextBlockStatus">A pointer to a NEXT_BLOCK_ENCRYPTION_STATUS struct</param>
/// <param name="encryptionAlgorithm">The drive's encryption algorithm for AES256-GCM</param>
/// <param name="keyAssociatedDataNextBlockLength">A pointer for storing an array of KAD lengths</param>
/// <param name="keyAssociatedDataNextBlock">A pointer for storing an array of KAD character arrays</param>
/// <returns>The next block encryption status</returns>
UCHAR
ParseNextBlockEncryptionStatus(PNEXT_BLOCK_ENCRYPTION_STATUS nextBlockStatus, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 keyAssociatedDataNextBlockLength, PCHAR* keyAssociatedDataNextBlock)
{
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	nextBlockStatus->PageCode = ntohs(nextBlockStatus->PageCode);
	nextBlockStatus->PageLength = ntohs(nextBlockStatus->PageLength);
	nextBlockStatus->BlockNumber = ntohll(nextBlockStatus->BlockNumber);
	int kadListLength = nextBlockStatus->PageLength - 12;
	printf("Parsing Next Block Encryption Status page...\n");
	printf("Page Length: %d bytes\n", nextBlockStatus->PageLength);
	printf("* Block Number: %llu\n", nextBlockStatus->BlockNumber);
	printf("* Compressed: %s\n", nextBlockStatus->CompressionStatus == 0x0 ? "Unable to determine" : "Unsupported value");
	printf("* Encryption Status: %s\n",
		nextBlockStatus->EncryptionStatus < NUMBER_OF_NEXT_BLOCK_ENCRYPTION_STATUS_STRINGS
		? NextBlockEncryptionStatusStrings[nextBlockStatus->EncryptionStatus]
		: NextBlockEncryptionStatusStrings[NUMBER_OF_NEXT_BLOCK_ENCRYPTION_STATUS_STRINGS - 1]
	);
	printf("* Encryption Mode External Status (EMES): %s\n", BOOLEAN_TO_STRING(nextBlockStatus->EncryptionModeExternalStatus));
	printf("* Raw Decryption Mode Disabled Status (RDMDS): %s\n", BOOLEAN_TO_STRING(nextBlockStatus->RawDecryptionModeDisabledStatus));
	printf("* Encryption Algorithm: %s (0x%02x)\n", encryptionAlgorithm != NULL && nextBlockStatus->AlgorithmIndex == encryptionAlgorithm->AlgorithmIndex ? "AES256-GCM" : "Unknown", nextBlockStatus->AlgorithmIndex);
	printf("* KAD Format: %s (0x%02X)\n",
		nextBlockStatus->KADFormat < NUMBER_OF_KAD_FORMAT_STRINGS
		? KadFormatStrings[nextBlockStatus->KADFormat]
		: KadFormatStrings[NUMBER_OF_KAD_FORMAT_STRINGS - 1],
		nextBlockStatus->KADFormat
	);
	printf("* KAD List Length: 0x%02x (%d bytes)\n", kadListLength, kadListLength);
	for (int i = 0; i < 2; i++)
	{
		keyAssociatedDataNextBlockLength[i] = 0;
		if (keyAssociatedDataNextBlock[i] != NULL)
		{
			free(keyAssociatedDataNextBlock[i]);
			keyAssociatedDataNextBlock[i] = NULL;
		}
	}
	PPLAIN_KEY_DESCRIPTOR kad = NULL;
	int currentKadTotalLength = 0;
	for (int i = 0; i < kadListLength; i += currentKadTotalLength)
	{
		UINT16 currentKadLength = nextBlockStatus->KADList[i + 2] << 8 | nextBlockStatus->KADList[i + 3];
		currentKadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[currentKadLength]);
		kad = calloc(currentKadTotalLength, 1);
		if (kad != NULL)
		{
			memcpy(kad, nextBlockStatus->KADList + i, currentKadTotalLength);
			printf("  * KAD Type: 0x%02x\n", kad->Type);
			printf("    * KAD Length: %d\n", currentKadLength);
			if (nextBlockStatus->KADFormat == SPOUT_TAPE_KAD_FORMAT_ASCII)
			{
				printf("    * KAD: %.*s\n", currentKadLength, kad->Descriptor);
				if (kad->Type < SPOUT_TAPE_KAD_PLAIN_TYPE_NONCE)
				{
					keyAssociatedDataNextBlock[kad->Type] = calloc(currentKadLength, sizeof(UCHAR));
					if (keyAssociatedDataNextBlock[kad->Type] != NULL)
					{
						memcpy(keyAssociatedDataNextBlock[kad->Type], kad->Descriptor, currentKadLength);
						keyAssociatedDataNextBlockLength[kad->Type] = currentKadLength;
					}
				}
			}
			else
			{
				fprintf(stderr, "Currently only able to display ASCII KADs.\n");
			}
			free(kad);
		}
	}
	printf("\n");
	return nextBlockStatus->EncryptionStatus;
}

/// <summary>
/// Compares two KAD arrays for equality
/// </summary>
/// <param name="keyAssociatedDataStatusLength">First array of KAD lengths</param>
/// <param name="keyAssociatedDataStatus">First array of KAD character arrays</param>
/// <param name="keyAssociatedDataNextBlockLength">Second array of KAD lengths</param>
/// <param name="keyAssociatedDataNextBlock">Second array of KAD character arrays</param>
/// <returns>TRUE if equal, otherwise FALSE</returns>
BOOL
KeyAuthenticatedDataIsEqual(PUINT16 keyAssociatedDataStatusLength, PCHAR* keyAssociatedDataStatus, PUINT16 keyAssociatedDataNextBlockLength, PCHAR* keyAssociatedDataNextBlock)
{
	printf("Comparing Data Encryption Status KAD and Next Block Encryption Status KAD...\n");
	BOOL statusValueExists = FALSE;
	BOOL nextBlockValueExists = FALSE;
	BOOL completeMatch = TRUE;
	BOOL isMatch = TRUE;

	for (int i = 0; i < 2; i++)
	{
		statusValueExists = keyAssociatedDataStatus[i] != NULL;
		nextBlockValueExists = keyAssociatedDataNextBlock[i] != NULL;
		if (!statusValueExists && !nextBlockValueExists) { continue; }
		printf("* KAD Type: 0x%02X\n", i);
		isMatch = TRUE;
		size_t kadLength = keyAssociatedDataNextBlockLength[i] > keyAssociatedDataStatusLength[i] ? keyAssociatedDataNextBlockLength[i] : keyAssociatedDataStatusLength[i];
		if (nextBlockValueExists)
		{
			printf("  * Data Encryption Status KAD: %.*s\n", (int)keyAssociatedDataStatusLength[i], keyAssociatedDataStatus[i]);
			printf("  * Next Block Encryption Status KAD: %.*s\n", (int)keyAssociatedDataNextBlockLength[i], keyAssociatedDataNextBlock[i]);
		}
		if (statusValueExists != nextBlockValueExists || keyAssociatedDataStatusLength[i] != keyAssociatedDataNextBlockLength[i])
		{
			completeMatch = FALSE;
			isMatch = FALSE;
		}
		else if (memcmp(keyAssociatedDataStatus[i], keyAssociatedDataNextBlock[i], kadLength) != 0)
		{
			completeMatch = FALSE;
			isMatch = FALSE;
		}
		if (statusValueExists || nextBlockValueExists)
		{
			printf("  * KAD of type 0x%02X %s.\n", i, isMatch ? "matches" : "doesn't match");
		}
	}
	if (completeMatch)
	{
		printf("* KAD matches.\n");
	}
	return completeMatch;
}

/// <summary>
/// Parse a pointer to a CERTIFICATE_DATA struct
/// </summary>
/// <param name="certificateData">A pointer to a CERTIFICATE_DATA struct</param>
VOID
ParseCertificateData(PCERTIFICATE_DATA certificateData)
{
	printf("Parsing Certificate data...\n");
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	certificateData->Length = ntohs(certificateData->Length);
	for (UINT16 i = 0; i < certificateData->Length; i++)
	{
		printf("%X", (certificateData->Certificate[i] & 0xFF) >> 4); // Upper 4 bits
		printf("%X", certificateData->Certificate[i] & 0x0F); // Lower 4 bits
	}
	printf("%s\n\n", certificateData->Length == 0 ? "* No certificate" : "");
}

/// <summary>
/// Set the remaining fields in a Set Data Encryption CDB
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="allocationLength">The size of the output buffer in bytes (must match total length of page including Page Code and Page Length fields)</param>
/// <param name="aesGcmAlgorithmIndex">The index of the AES256-GCM algorithm in the device</param>
/// <param name="clearKey">TRUE if encryption keys are being cleared, FALSE if they are being set</param>
/// <param name="keyFormat">The key format</param>
/// <param name="keyFieldLength">The length of the Key field character array</param>
/// <param name="keyField">A character array containing a Key field</param>
/// <param name="kadFieldLength">The size of the PPLAIN_KEY_DESCRIPTOR struct in bytes</param>
/// <param name="kad">A pointer to a PPLAIN_KEY_DESCRIPTOR struct</param>
VOID
SetDataEncryption(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UINT32 allocationLength, UCHAR aesGcmAlgorithmIndex, BOOL clearKey, UCHAR keyFormat, UINT16 keyFieldLength, PUCHAR keyField, int kadFieldLength, PPLAIN_KEY_DESCRIPTOR kad)
{
	printf("* Finalising CDB...\n");
	psptwb_ex->spt.Cdb[6] = (allocationLength >> 24) & 0xFF;
	psptwb_ex->spt.Cdb[7] = (allocationLength >> 16) & 0xFF;
	psptwb_ex->spt.Cdb[8] = (allocationLength >> 8) & 0xFF;
	psptwb_ex->spt.Cdb[9] = allocationLength & 0xFF;
	UINT16 pageLength = (UINT16)(allocationLength - 4);
	psptwb_ex->spt.DataOutTransferLength = 4 + (size_t)pageLength;

	PKEY_HEADER keyHeader = calloc(4 + (size_t)pageLength, sizeof(UCHAR));
	if (keyHeader != NULL)
	{
		keyHeader->PageCode = htons(SPOUT_TAPE_SET_DATA_ENCRYPTION);
		printf("  * Page Length: 0x%04x (%d bytes)\n", pageLength, pageLength);
		keyHeader->PageLength = htons(pageLength);
		keyHeader->Scope = 0x2;
		keyHeader->EncryptionMode = clearKey ? 0x0 : 0x2;
		keyHeader->DecriptionMode = clearKey ? 0x0 : 0x2;
		keyHeader->AlgorithmIndex = aesGcmAlgorithmIndex;
		keyHeader->KeyFormat = (UCHAR)keyFormat;
		printf("  * Key format: 0x%02x\n", keyFormat);
		if (kad != NULL) {
			keyHeader->KADFormat = SPOUT_TAPE_KAD_FORMAT_ASCII;
		}
		printf("  * Key field length: 0x%04x (%d bytes)\n", keyFieldLength, keyFieldLength);
		keyHeader->KeyLength = htons(keyFieldLength);
		if (keyField != NULL)
		{
			memcpy(keyHeader->KeyAndKADList, keyField, keyFieldLength);
			free(keyField);
		}
		if (kad != NULL)
		{
			memcpy(keyHeader->KeyAndKADList + keyFieldLength, kad, kadFieldLength);
			free(kad);
		}
		memcpy(psptwb_ex->ucDataBuf, keyHeader, allocationLength);
		free(keyHeader);
	}
}

/// <summary>
/// Process Key-Associated Data and generate a KAD field
/// </summary>
/// <param name="clearKey">TRUE if encryption keys are being cleared, FALSE if they are being set</param>
/// <param name="keyAssociatedDataLength">The length of the Key-Associated Data character array</param>
/// <param name="keyAssociatedData">A character array containing Key-Associated Data</param>
/// <param name="encryptionAlgorithm">The drive's encryption algorithm for AES256-GCM</param>
/// <param name="kadFieldLength">The length of the KAD field</param>
/// <param name="ppKadField">A pointer to a PPLAIN_KEY_DESCRIPTOR struct that will point at the new PLAIN_KEY_DESCRIPTOR[]</param>
/// <returns>TRUE if successful, otherwise FALSE</returns>
BOOL
ProcessKad(BOOL clearKey, UINT16 keyAssociatedDataLength, PUCHAR keyAssociatedData, PDATA_ENCRYPTION_ALGORITHM encryptionAlgorithm, PUINT16 kadFieldLength, PPLAIN_KEY_DESCRIPTOR* ppKadField)
{
	printf("* Processing KAD...\n");
	*kadFieldLength = 0;

	// Return early if there is no KAD to process
	if (clearKey || keyAssociatedData == NULL)
	{
		return TRUE;
	}

	UINT16 maxKadLength = encryptionAlgorithm->KadFormatCapable ? encryptionAlgorithm->AuthKadMaxLength + encryptionAlgorithm->UnauthKadMaxLength : encryptionAlgorithm->AuthKadMaxLength;

	// Inform if KADF is not supported - KADF required for binary/ASCII KAD, required for splitting a descriptor between A-KAD and U-KAD fields
	if (!encryptionAlgorithm->KadFormatCapable)
	{
		// If A-KAD length is fixed (AKADF), does the descriptor meet the required length?
		if (encryptionAlgorithm->AuthKadFixedLength && keyAssociatedDataLength != encryptionAlgorithm->AuthKadMaxLength)
		{
			fprintf(stderr, "  * Key-Associated Data (KAD) must be exactly %d ASCII characters long. Padding A-KAD with %d NUL characters.\n",
				encryptionAlgorithm->AuthKadMaxLength,
				encryptionAlgorithm->AuthKadMaxLength - keyAssociatedDataLength
			);
		}
		printf("  * KAD Format (KADF) is not supported by your drive and/or the encryption algorithm. KAD maximum length limited to %d A-KAD bytes.\n", encryptionAlgorithm->AuthKadMaxLength);
	}
	// If KADF is supported, and descriptor overflows both A-KAD and U-KAD Fields
	else if (encryptionAlgorithm->KadFormatCapable && keyAssociatedDataLength > maxKadLength)
	{
		fprintf(stderr, "** ERROR: Key-Associated Data (KAD) length limit is %d ASCII characters.\n", maxKadLength);
		return FALSE;
	}
	// If KADF is supported, and descriptor overflows A-KAD field
	else if (encryptionAlgorithm->KadFormatCapable && keyAssociatedDataLength > encryptionAlgorithm->AuthKadMaxLength)
	{
		// If U-KAD length is fixed (UKADF), does the part of the descriptor that doesn't fit in A-KAD have the required length?
		if (encryptionAlgorithm->UnauthKadFixedLength && keyAssociatedDataLength - encryptionAlgorithm->AuthKadMaxLength != encryptionAlgorithm->UnauthKadMaxLength)
		{
			fprintf(stderr, "  * Key-Associated Data (KAD) must be exactly %d or %d ASCII characters long. Padding U-KAD with %d NUL characters.\n",
				encryptionAlgorithm->AuthKadMaxLength,
				encryptionAlgorithm->AuthKadMaxLength + encryptionAlgorithm->UnauthKadMaxLength,
				encryptionAlgorithm->AuthKadMaxLength + encryptionAlgorithm->UnauthKadFixedLength - encryptionAlgorithm->UnauthKadFixedLength
			);
		}
		// Inform A-KAD and U-KAD will be used
		printf("  * KAD Format (KADF) is supported by your drive and your key description is longer than will fit in A-KAD. KAD will be split between A-KAD and U-KAD.\n");
	}
	// If KADF is supported, and descriptor doesn't overflow A-KAD field
	else if (encryptionAlgorithm->KadFormatCapable && keyAssociatedDataLength <= encryptionAlgorithm->AuthKadMaxLength)
	{
		// If A-KAD length is fixed (AKADF), does the descriptor meet the required length?
		if (encryptionAlgorithm->AuthKadFixedLength && keyAssociatedDataLength != encryptionAlgorithm->AuthKadMaxLength)
		{
			fprintf(stderr, "** ERROR: Key-Associated Data (KAD) must be exactly %d or %d ASCII characters long.\n",
				encryptionAlgorithm->AuthKadMaxLength,
				encryptionAlgorithm->AuthKadMaxLength + encryptionAlgorithm->UnauthKadMaxLength
			);
			return FALSE;
		}
		// Inform only A-KAD will be used
		printf("  * KAD Format (KADF) is supported by your drive and your key description will fit in A-KAD. KAD will only use A-KAD.\n");
	}

	// Calculate the length of aKad->Descriptor
	UINT16 aKadDescriptorLength = 0;
	if (encryptionAlgorithm->AuthKadFixedLength || keyAssociatedDataLength > encryptionAlgorithm->AuthKadMaxLength)
	{
		aKadDescriptorLength = encryptionAlgorithm->AuthKadMaxLength;
	}
	else
	{
		aKadDescriptorLength = keyAssociatedDataLength;
	}
	// Calculate the length of aKad
	UINT16 aKadLength = (UINT16)FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[aKadDescriptorLength]);
	// Calculate the length of uKad->Descriptor
	UINT16 uKadDescriptorLength = 0;
	if (encryptionAlgorithm->UnauthKadFixedLength && keyAssociatedDataLength > encryptionAlgorithm->AuthKadMaxLength)
	{
		uKadDescriptorLength = encryptionAlgorithm->UnauthKadMaxLength;
	}
	else if (keyAssociatedDataLength > encryptionAlgorithm->AuthKadMaxLength)
	{
		uKadDescriptorLength = keyAssociatedDataLength - encryptionAlgorithm->AuthKadMaxLength;
	}
	// Calculate the length of uKad
	UINT16 uKadLength = uKadDescriptorLength == 0 ? 0 : (UINT16)FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[uKadDescriptorLength]);

	// Calculate the combined lengths of aKad and uKad
	*kadFieldLength = aKadLength + uKadLength;
	// Allocate memory to store KAD list
	PUCHAR kadField = calloc(*kadFieldLength, sizeof(UCHAR));
	if (kadField == NULL)
	{
		return FALSE;
	}
	// Update pointer for KAD list to new location
	*ppKadField = (PPLAIN_KEY_DESCRIPTOR)kadField;
	// U-KAD descriptor (0x00) comes before A-KAD descriptor (0x01) in KAD list; set pointers for both
	PPLAIN_KEY_DESCRIPTOR uKad = (PPLAIN_KEY_DESCRIPTOR)kadField;
	PPLAIN_KEY_DESCRIPTOR aKad = (PPLAIN_KEY_DESCRIPTOR)(kadField + uKadLength);
	// Create U-KAD if necessary
	if (keyAssociatedDataLength > encryptionAlgorithm->AuthKadMaxLength)
	{
		uKad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_UNAUTH;
		uKad->Length[0] = (uKadDescriptorLength & 0xFF00) >> 8;
		uKad->Length[1] = uKadDescriptorLength & 0xFF;
		memcpy(uKad->Descriptor, keyAssociatedData + aKadDescriptorLength, uKadDescriptorLength);
		printf("  * KAD Descriptor of type 0x%02x with length %d\n", uKad->Type, uKadLength);
	}
	// Create A-KAD
	aKad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH;
	aKad->Length[0] = (aKadDescriptorLength & 0xFF00) >> 8;
	aKad->Length[1] = aKadDescriptorLength & 0xFF;
	memcpy(aKad->Descriptor, keyAssociatedData, aKadDescriptorLength);
	printf("  * KAD Descriptor of type 0x%02x with length %d\n", aKad->Type, aKadLength);

	return TRUE;
}

/// <summary>
/// Process an encryption key and generate a Key field
/// </summary>
/// <param name="keyFormat">The key format</param>
/// <param name="keyType">The key type</param>
/// <param name="keyLength">The length of the key character array</param>
/// <param name="key">A character array containing the key</param>
/// <param name="wrappedDescriptorsLength">The length of the wrapped key descriptor character array</param>
/// <param name="wrappedDescriptors">A character array containing wrapped key descriptors</param>
/// <param name="pKeyField">A pointer to a character array for storing the Key field</param>
/// <returns>The length of the key field</returns>
UINT16
ProcessKey(int keyFormat, int keyType, int keyLength, PUCHAR key, UINT16 wrappedDescriptorsLength, PUCHAR wrappedDescriptors, PUCHAR* pKeyField)
{
	printf("* Processing key...\n");
	UINT16 keyFieldLength = 0;
	PUCHAR keyField = NULL;
	// LTO encryption uses 256 bit (32 byte) keys; assume larger keys are hex rather than binary
	BOOL keyIsHex = keyLength > 32;
	if (keyIsHex) {
		keyLength = keyLength / 2;
	}

	if (keyFormat == SPIN_TAPE_KEY_FORMAT_PLAIN)
	{
		keyFieldLength = (UINT16)keyLength;
		keyField = calloc(keyFieldLength, sizeof(UCHAR));
		if (keyField == NULL)
		{
			return 0;
		}
		*pKeyField = keyField;
		if (keyIsHex)
		{
			UCHAR temp[3] = { 0 };
			for (int i = 0; i < keyLength; i++)
			{
				memcpy(temp, &key[i * 2], 2);
				keyField[i] = strtol((char*)temp, NULL, 16) & 0xFF;
			}
		}
		else
		{
			memcpy(keyField, key, keyLength);
		}
	}
	else if (keyFormat == SPIN_TAPE_KEY_FORMAT_WRAPPED)
	{
		if (keyFormat < 0 || keyFormat > 0xFFFF ||
			keyType < 0 || keyType > 0xFFFF ||
			keyLength < 0 || keyLength > 0xFFFF)
		{
			fprintf(stderr, "  * Error: A parameter to ProcessKey() was out of UINT16 bounds.\n");
		}

		UINT16 offset = 0;
		UINT16 parameterSet, labelLength, wrappedKeyLength, signatureLength = 0;
		keyFieldLength = (UINT16)(sizeof(parameterSet) + sizeof(labelLength) + wrappedDescriptorsLength + sizeof(wrappedKeyLength) + keyLength + sizeof(signatureLength));
		keyField = calloc(keyFieldLength, sizeof(UCHAR));
		if (keyField == NULL)
		{
			return 0;
		}
		*pKeyField = keyField;

		parameterSet = htons(keyType & 0xFFFF);
		memcpy(keyField + offset, &parameterSet, sizeof(parameterSet));
		offset += sizeof(parameterSet);

		labelLength = htons(wrappedDescriptorsLength & 0xFFFF);
		memcpy(keyField + offset, &labelLength, sizeof(labelLength));
		offset += sizeof(labelLength);
		memcpy(keyField + offset, wrappedDescriptors, wrappedDescriptorsLength);
		offset += wrappedDescriptorsLength;

		wrappedKeyLength = htons(keyLength & 0xFFFF);
		memcpy(keyField + offset, &wrappedKeyLength, sizeof(wrappedKeyLength));
		offset += sizeof(wrappedKeyLength);

		UCHAR temp[3] = { 0 };
		for (int i = 0; i < keyLength; i++)
		{
			memcpy(temp, &key[i * 2], 2);
			keyField[offset + i] = strtol((char*)temp, NULL, 16) & 0xFF;
		}
		offset += (UINT16)keyLength;

		signatureLength = htons(0);
		memcpy(keyField + offset, &signatureLength, sizeof(signatureLength));
	}

	return keyField != NULL ? keyFieldLength : 0;
}

/// <summary>
/// Convert a SCSI OpCode to CDB length in bytes (does not support variable length CDBs)
/// </summary>
/// <param name="opCode">SCSI OpCode</param>
/// <returns>0 if not supported, otherwise length of CDB in bytes</returns>
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

/// <summary>
/// Create a STORAGE_REQUEST_BLOCK for a CDB OpCode (direction: in/read)
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="opCode">SCSI OpCode</param>
/// <returns>Length of the SRB in bytes</returns>
ULONG
ResetSrbIn(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode)
{
	UCHAR cdbLength = GetCdbLength(opCode);
	if (cdbLength == 0) { return cdbLength; }

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
	switch (opCode)
	{
	case SCSIOP_INQUIRY:
		psptwb_ex->spt.Cdb[0] = opCode;
		psptwb_ex->spt.Cdb[3] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		psptwb_ex->spt.Cdb[4] = SPTWB_DATA_LENGTH & 0xFF;
		break;
	case SCSIOP_SECURITY_PROTOCOL_IN:
		psptwb_ex->spt.Cdb[0] = opCode;
		psptwb_ex->spt.Cdb[6] = (SPTWB_DATA_LENGTH >> 24) & 0xFF;
		psptwb_ex->spt.Cdb[7] = (SPTWB_DATA_LENGTH >> 16) & 0xFF;
		psptwb_ex->spt.Cdb[8] = (SPTWB_DATA_LENGTH >> 8) & 0xFF;
		psptwb_ex->spt.Cdb[9] = SPTWB_DATA_LENGTH & 0xFF;
		break;
	default:
		break;
	}
	return offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf) +
		psptwb_ex->spt.DataInTransferLength;
}

/// <summary>
/// Create a STORAGE_REQUEST_BLOCK for a CDB OpCode (direction: out/write)
/// </summary>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="opCode">SCSI OpCode</param>
/// <returns>Length of the SRB in bytes</returns>
ULONG
ResetSrbOut(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, UCHAR opCode)
{
	UCHAR cdbLength = GetCdbLength(opCode);
	if (cdbLength == 0) { return cdbLength; }

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
	psptwb_ex->spt.DataOutBufferOffset =
		offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf);
	psptwb_ex->spt.DataInBufferOffset = 0;
	switch (opCode)
	{
	case SCSIOP_SECURITY_PROTOCOL_OUT:
		psptwb_ex->spt.Cdb[0] = opCode;
		break;
	default:
		break;
	}
	return offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf) +
		psptwb_ex->spt.DataOutTransferLength;
}

/// <summary>
/// Converts a SCSI Security Protocol integer to a string description
/// </summary>
/// <param name="securityProtocol">Unsigned byte assigned to a security protocol</param>
/// <returns>English description of the security protocol</returns>
PCHAR
GetSecurityProtocolDescription(UCHAR securityProtocol)
{
	switch (securityProtocol)
	{
	case SECURITY_PROTOCOL_INFO:
		return "Security protocol information";
	case SECURITY_PROTOCOL_TCG1:
	case SECURITY_PROTOCOL_TCG2:
	case SECURITY_PROTOCOL_TCG3:
	case SECURITY_PROTOCOL_TCG4:
	case SECURITY_PROTOCOL_TCG5:
	case SECURITY_PROTOCOL_TCG6:
		return "TCG";
	case SECURITY_PROTOCOL_TAPE:
		return "Tape Data Encryption (SSC-3)";
	case SECURITY_PROTOCOL_ADC3:
		return "Data Encryption Configuration (ADC-3)";
	case SECURITY_PROCOCOL_SA_CREATION_CAPABILITIES:
		return "SA Creation Capabilities (SPC-5)";
	case SECURITY_PROCOCOL_IKEV2_SCSI:
		return "IKEv2-SCSI (SPC-5)";
	case SECURITY_PROCOCOL_UFS:
		return "JEDEC Universal Flash Storage (UFS)";
	case SECURITY_PROCOCOL_SD_TRUSTEDFLASH:
		return "SDcard TrustedFlash Security Systems Specification 1.1.3";
	case SECURITY_PROTOCOL_IEEE1667:
		return "IEEE 1667";
	case SECURITY_PROCOCOL_ATA_PASSWORD:
		return "ATA Device Server Password Security (SAT-3)";
	default:
		return "Unknown";
	}
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
		fprintf(stderr, "%s\n", errorBuffer);
	}
	else {
		fprintf(stderr, "Format message failed.  Error: %d\n", GetLastError());
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


/// <summary>
/// Checks the status of an SRB/CDB is good
/// </summary>
/// <param name="fileHandle">Open HANDLE to the device</param>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <param name="status">Status returned from DeviceIoControl</param>
/// <param name="returned">Length of returned data in bytes</param>
/// <param name="length">Length of the SRB in bytes</param>
/// <returns>TRUE if good, FALSE if bad</returns>
BOOL
CheckStatus(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, BOOL status, ULONG length, DWORD returned)
{
	if (status && psptwb_ex->spt.ScsiStatus == SCSISTAT_GOOD)
	{
		return TRUE;
	}
	else if (!status && psptwb_ex->spt.ScsiStatus == SCSISTAT_GOOD)
	{
		return WaitForSenseChange(fileHandle, psptwb_ex);
	}
	else if (!status || psptwb_ex->spt.ScsiStatus != SCSISTAT_GOOD)
	{
		printf("Status: 0x%02X, SCSI Status: 0x%02x\n", status, psptwb_ex->spt.ScsiStatus);
		PrintStatusResultsEx(status, returned, psptwb_ex, length);
		return FALSE;
	}
	else
	{
		printf("Unreachable?\n");
		return FALSE;
	}
}

/// <summary>
/// Waits for sense key to change from NO SENSE (0x0)
/// </summary>
/// <param name="fileHandle">Open HANDLE to the device</param>
/// <param name="psptwb_ex">Pointer to a SCSI_PASS_THROUGH_WITH_BUFFERS_EX struct (wrapper of SCSI_PASS_THROUGH_EX)</param>
/// <returns>TRUE on sense key change, FALSE if it didn't change before reaching maximum retries</returns>
BOOL
WaitForSenseChange(HANDLE fileHandle, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex)
{
	BOOL status;
	ULONG length;
	DWORD returned;
	printf("Waiting for sense change...");

	PSENSE_INFO senseInfo = (PSENSE_INFO)psptwb_ex->ucSenseBuf;
	UCHAR retriesRemaining = 10;
	while (senseInfo->SenseKey == 0 && retriesRemaining > 0)
	{
		length = ResetSrbIn(psptwb_ex, SCSIOP_REQUEST_SENSE);
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);
		printf(".");
		senseInfo = (PSENSE_INFO)psptwb_ex->ucSenseBuf;
		retriesRemaining--;
		Sleep(1000);
	}
	printf("\n");
	if (senseInfo->SenseKey != 0)
	{
		PrintSenseInfoEx(psptwb_ex);
		return TRUE;
	}
	else
	{
		printf("Giving up.\n");
		return FALSE;
	}
}

VOID
PrintStatusResultsEx(
	BOOL status, DWORD returned, PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex,
	ULONG length)
{
	ULONG errorCode;

	if (!status) {
		fprintf(stderr, "Error: %d  ",
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
	printf("* Scsi status: %02Xh\n", psptwb_ex->spt.ScsiStatus);
	if (psptwb_ex->spt.SenseInfoLength == 0) {
		return;
	}
	printf("* Sense Info -- consult SCSI spec for details\n");
	PSENSE_INFO senseInfo = (PSENSE_INFO)psptwb_ex->ucSenseBuf;
	PCHAR description = NULL;
	switch (senseInfo->ErrorCode)
	{
	case 0x70:
		description = "Current";
		break;
	case 0x71:
		description = "Deferred";
		break;
	default:
		description = "Unknown";
		break;
	}
	printf("  * Error Code: 0x%02X (%s)\n", senseInfo->ErrorCode, description);
	printf("  * Sense Key: 0x%02X (%s)\n", senseInfo->SenseKey, SenseKeyStrings[senseInfo->SenseKey]);
	printf("  * ASC/ASCQ: 0x%02X/0x%02X\n", senseInfo->AdditionalSenseCode, senseInfo->AdditionalSenseCodeQualifier);
	if (senseInfo->SenseKeySpecificValid == 0b0)
	{
		printf("  * Product Specific Error Code: 0x%02X\n", senseInfo->FieldPointer[1]);
	}
	else if (senseInfo->SenseKeySpecificValid == 0b1)
	{
		UINT16 fieldPointer = senseInfo->FieldPointer[0] << 8 | senseInfo->FieldPointer[1];
		float progress;
		switch (senseInfo->SenseKey)
		{
		case 0x0:
		case 0x2:
			progress = (float)fieldPointer / 65536 * 100;
			printf("    * Progress: %.2f%%\n", progress);
			break;
		case 0x5:
			printf("    * Field Pointer (%s): 0x%04X\n", senseInfo->CommandData == 0b0 ? "Parameter List" : "CDB", fieldPointer);
			break;
		}
		printf("    * Bit Pointer: 0%o\n", senseInfo->BitPointer);
	}
	printf("  * Drive %s cleaning.\n", senseInfo->CleanNeeded ? "needs" : "doesn't need");
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
		fprintf(stderr, "   ***** No adapter descriptor supported on the device *****\n");
	}
	else {
		PrintAdapterDescriptor(adapterDescriptor);
		*AlignmentMask = adapterDescriptor->AlignmentMask;
		*SrbType = adapterDescriptor->SrbType;
	}

	if (deviceDescriptor == NULL) {
		fprintf(stderr, "   ***** No device descriptor supported on the device  *****\n");
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

