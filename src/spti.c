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
	DWORD accessMode = 0, shareMode = 0;
	HANDLE fileHandle = NULL;
	ULONG alignmentMask = 0; // default == no alignment requirement
	UCHAR srbType = SRB_TYPE_SCSI_REQUEST_BLOCK; // default == SRB_TYPE_SCSI_REQUEST_BLOCK
	STORAGE_BUS_TYPE storageBusType = BusTypeUnknown;
	PUCHAR pUnAlignedBuffer = NULL;
	PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex = calloc(1, sizeof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX));
	CHAR string[NAME_COUNT];

	ULONG length = 0,
		errorCode = 0,
		returned = 0;

	if ((argc < 2) || (argc > 4)) {
		fprintf(stderr, "Usage:  %s <port-name> [key] [kad]\n", argv[0]);
		fprintf(stderr, "Examples:\n");
		fprintf(stderr, "    spti Tape0                    (open the tape class driver in SHARED READ mode)\n");
		fprintf(stderr, "    spti Tape0 D00D00             (Use RFC 3447 wrapped key 0xD00D00 on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 D00D00 BackupTape1 (Use RFC 3447 wrapped key 0xD00D00 and KAD BackupTape1 on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 weak               (Use a hardcoded really weak test key on drive Tape0)\n");
		fprintf(stderr, "    spti Tape0 none               (Disable encryption and decryption on drive Tape0)\n");
		return;
	}

	StringCbPrintf(string, sizeof(string), "\\\\.\\%s", argv[1]);

	shareMode = FILE_SHARE_READ;
	accessMode = GENERIC_WRITE | GENERIC_READ;
	UINT16 logicalUnitIdentifierLength = 0;
	PUCHAR logicalUnitIdentifier = NULL;
	PDATA_ENCRYPTION_CAPABILITIES encryptionCapabilities = NULL;
	BOOL capTapeEncryption = FALSE;
	BOOL capRfc3447 = FALSE;
	INT16 aesGcmAlgorithmIndex = -1; // Index is 8 bytes unsigned (UCHAR) in SCSI, extra byte is used for status
	int wrappedDescriptorsLength = 0;
	PUCHAR wrappedDescriptors = NULL;
	int keyType = -1;
	int keyFormat = -1;
	int keyLength = 0;
	PUCHAR key = NULL;
	BOOL testKey = FALSE;
	BOOL noKey = FALSE;
	PUCHAR keyAssociatedData = NULL;

	if (argc > 2) {
		if (strcmp(argv[2], "weak") == 0) {
			testKey = TRUE;
		}
		else if (strcmp(argv[2], "none") == 0) {
			noKey = TRUE;
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

	fileHandle = CreateFile(string,
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
				ParseDataEncryptionCapabilities((PDATA_ENCRYPTION_CAPABILITIES)psptwb_ex->ucDataBuf, &encryptionCapabilities, &aesGcmAlgorithmIndex);
			}
		}


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
				ParseDataEncryptionStatus((PDATA_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, aesGcmAlgorithmIndex);
			}
		}


		/*
		* If the device supports AES key wrapping (RFC 3447), try to obtain the public key
		*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Device Server Key Wrapping Public Key page
		*/
		if (capRfc3447)
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
	}


	/*
	* Send a wrapped key to the drive if wrapped keys are supported and supplied key is in wrapped format
	*
	* CDB: Security Protocol Out, Set Data Encryption page, Key Format 0x02 (Wrapped)
	*/
	if (capRfc3447 && keyFormat == SPIN_TAPE_KEY_FORMAT_WRAPPED && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		int wrappedKeyLength = keyLength / 2;
		printf("Wrapped key length: %d bytes\n", wrappedKeyLength);

		if (aesGcmAlgorithmIndex == -1)
		{
			fprintf(stderr, "AES-GCM algorithm index not found.\n\n");
			goto Cleanup;
		}

		printf("AES-GCM algorithm index: 0x%02x\n\n", aesGcmAlgorithmIndex);

		int kadTotalLength = 0;
		PPLAIN_KEY_DESCRIPTOR kad = NULL;
		if (!noKey && keyAssociatedData != NULL) {
			int kadLength = (int)strlen((char*)keyAssociatedData);
			if (encryptionCapabilities->AuthKadFixedLength || kadLength > encryptionCapabilities->AuthKadMaxLength)
			{
				fprintf(stderr, "Key-Associated Data (KAD) must currently be %d ASCII characters%s - other options are not implemented.\n", encryptionCapabilities->AuthKadMaxLength, encryptionCapabilities->AuthKadFixedLength ? "" : " or fewer");
				goto Cleanup;
			}
			kadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[kadLength]);
			kad = malloc(kadTotalLength);
			ZeroMemory(kad, sizeof(PLAIN_KEY_DESCRIPTOR));
			kad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH; // TODO: Check length is less than *Maximum Authenticated Key-Associated Data Bytes*
			kad->Length[0] = (kadLength & 0xFF00) >> 8;
			kad->Length[1] = kadLength & 0xFF;
			memcpy(kad->Descriptor, keyAssociatedData, kadLength);
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
		keyHeader.AlgorithmIndex = (UCHAR)aesGcmAlgorithmIndex;
		keyHeader.KeyFormat = (UCHAR)keyFormat;
		if (kad != NULL) {
			keyHeader.KADFormat = SPOUT_TAPE_KAD_FORMAT_ASCII;
		}

		int wrappedKeyTotalLength = 4 + wrappedDescriptorsLength + 2 + wrappedKeyLength + 2;
		PUCHAR wrappedKey = calloc(wrappedKeyTotalLength, 1);
		wrappedKey[0] = (keyType >> 8) & 0xFF;
		wrappedKey[1] = keyType & 0xFF;
		wrappedKey[2] = (wrappedDescriptorsLength >> 8) & 0xFF;
		wrappedKey[3] = wrappedDescriptorsLength & 0xFF;
		if (wrappedDescriptors != NULL)
		{
			memcpy(wrappedKey + 4, wrappedDescriptors, wrappedDescriptorsLength);
			wrappedKey[4 + wrappedDescriptorsLength + 0] = (wrappedKeyLength >> 8) & 0xFF;
			wrappedKey[4 + wrappedDescriptorsLength + 1] = wrappedKeyLength & 0xFF;
			UCHAR temp[3] = { 0 };
			for (int i = 0; i < wrappedKeyLength; i++)
			{
				memcpy(temp, &key[i * 2], 2);
				wrappedKey[4 + wrappedDescriptorsLength + 2 + i] = strtol((char*)temp, NULL, 16) & 0xFF;
			}
		}

		int pageLength = sizeof(KEY_HEADER) - 4 + 2 + wrappedKeyTotalLength + kadTotalLength;
		keyHeader.PageLength[0] = (pageLength >> 8) & 0xFF;
		keyHeader.PageLength[1] = pageLength & 0xFF;

		length = ResetSrbOut(psptwb_ex, CDB12GENERIC_LENGTH);
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
		memcpy(psptwb_ex->spt.Cdb, &spout, sizeof(struct _SECURITY_PROTOCOL_OUT));
		printf("Security Protocol Out:\n\n");
		PrintDataBuffer(psptwb_ex->spt.Cdb, sizeof(spout));
		psptwb_ex->spt.DataOutTransferLength = allocationLength;

		memcpy(psptwb_ex->ucDataBuf, &keyHeader, sizeof(keyHeader));
		psptwb_ex->ucDataBuf[sizeof(keyHeader) + 0] = (wrappedKeyTotalLength >> 8) & 0xFF;
		psptwb_ex->ucDataBuf[sizeof(keyHeader) + 1] = wrappedKeyTotalLength & 0xFF;
		if (wrappedKey != NULL) {
			memcpy(psptwb_ex->ucDataBuf + sizeof(keyHeader) + 2, wrappedKey, wrappedKeyTotalLength);
			free(wrappedKey);
		}
		if (kad != NULL) {
			memcpy(psptwb_ex->ucDataBuf + sizeof(keyHeader) + 2 + wrappedKeyTotalLength, kad, kadTotalLength);
			free(kad);
		}

		printf("SRB length: %d (0x%02x)\n", length, length);
		printf("Buffer length: %d (0x%02x)\n\n", allocationLength, allocationLength);
		printf("Buffer:\n\n");
		PrintDataBuffer((PUCHAR)psptwb_ex->ucDataBuf, psptwb_ex->spt.DataOutTransferLength);

		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		CheckStatus(fileHandle, psptwb_ex, status, returned, length);
	}

	/*
	* If command parameter for key is set to string "weak", set a hardcoded weak key
	* If command parameter for key is set to string "none", remove keys from drive
	*
	* CDB: Security Protocol Out, Set Data Encryption page, Key Format 0x00 (Plain)
	*/
	if ((testKey || noKey) && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		if (aesGcmAlgorithmIndex == -1)
		{
			fprintf(stderr, "AES-GCM algorithm index not found.\n\n");
			goto Cleanup;
		}

		printf("AES-GCM algorithm index: 0x%02x\n\n", aesGcmAlgorithmIndex);

		int kadTotalLength = 0;
		PPLAIN_KEY_DESCRIPTOR kad = NULL;
		if (!noKey && keyAssociatedData != NULL) {
			int kadLength = (int)strlen((char*)keyAssociatedData);
			if (encryptionCapabilities->AuthKadFixedLength || kadLength > encryptionCapabilities->AuthKadMaxLength)
			{
				fprintf(stderr, "Key-Associated Data (KAD) must currently be %d ASCII characters%s - other options are not implemented.\n", encryptionCapabilities->AuthKadMaxLength, encryptionCapabilities->AuthKadFixedLength ? "" : " or fewer");
				goto Cleanup;
			}
			kadTotalLength = FIELD_OFFSET(PLAIN_KEY_DESCRIPTOR, Descriptor[kadLength]);
			kad = malloc(kadTotalLength);
			ZeroMemory(kad, sizeof(PLAIN_KEY_DESCRIPTOR));
			kad->Type = SPOUT_TAPE_KAD_PLAIN_TYPE_AUTH; // TODO: Check length is less than *Maximum Authenticated Key-Associated Data Bytes*
			kad->Length[0] = (kadLength & 0xFF00) >> 8;
			kad->Length[1] = kadLength & 0xFF;
			memcpy(kad->Descriptor, keyAssociatedData, kadLength);
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
		plainKey->AlgorithmIndex = (UCHAR)aesGcmAlgorithmIndex;
		if (keyFormat >= 0)
		{
			plainKey->KeyFormat = (UCHAR)keyFormat;
		}
		plainKey->KADFormat = keyAssociatedData != NULL ? 0x0 : SPOUT_TAPE_KAD_FORMAT_ASCII;
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

		length = ResetSrbOut(psptwb_ex, CDB12GENERIC_LENGTH);
		struct _SECURITY_PROTOCOL_OUT spout = { '\0' };
		spout.OperationCode = SCSIOP_SECURITY_PROTOCOL_OUT;
		spout.SecurityProtocol = SECURITY_PROTOCOL_TAPE; // tape encryption
		spout.SecurityProtocolSpecific[0] = (SPOUT_TAPE_SET_DATA_ENCRYPTION >> 8) & 0xFF; // device server key wrapping public key page
		spout.SecurityProtocolSpecific[1] = SPOUT_TAPE_SET_DATA_ENCRYPTION & 0xFF;
		spout.AllocationLength[0] = (plainKeyTotalLength >> 24) & 0xFF;
		spout.AllocationLength[1] = (plainKeyTotalLength >> 16) & 0xFF;
		spout.AllocationLength[2] = (plainKeyTotalLength >> 8) & 0xFF;
		spout.AllocationLength[3] = plainKeyTotalLength & 0xFF;
		memcpy(psptwb_ex->spt.Cdb, &spout, sizeof(struct _SECURITY_PROTOCOL_OUT));
		printf("Security Protocol Out:\n\n");
		PrintDataBuffer(psptwb_ex->spt.Cdb, sizeof(spout));

		memcpy(psptwb_ex->ucDataBuf, plainKey, plainKeyTotalLength);
		free(plainKey);
		psptwb_ex->spt.DataOutTransferLength = plainKeyTotalLength;

		printf("Buffer length: %d (0x%02x)\n\n", plainKeyTotalLength, plainKeyTotalLength);
		printf("SRB length: %d (0x%02x)\n\n", length, length);

		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		printf("Cdb:\n\n");
		PrintDataBuffer(psptwb_ex->spt.Cdb, psptwb_ex->spt.CdbLength);
		printf("Buffer:\n\n");
		PrintDataBuffer((PUCHAR)psptwb_ex->ucDataBuf, psptwb_ex->spt.DataOutTransferLength);

		CheckStatus(fileHandle, psptwb_ex, status, returned, length);
	}

	if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
	{
		/*
		* CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Status page
		*/
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_STATUS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			int pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_ENCRYPTION_STATUS) {
				ParseDataEncryptionStatus((PDATA_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, aesGcmAlgorithmIndex);
			}
		}


		// CDB: Security Protocol In, Tape Data Encryption Security Protocol, Next Block Encryption Status page
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			int pageCode = psptwb_ex->ucDataBuf[0] << 8 | psptwb_ex->ucDataBuf[1];
			if (pageCode == SPIN_TAPE_NEXT_BLOCK_ENCRYPTION_STATUS) {
				ParseNextBlockEncryptionStatus((PNEXT_BLOCK_ENCRYPTION_STATUS)psptwb_ex->ucDataBuf, aesGcmAlgorithmIndex);
			}
		}

		// CDB: Security Protocol In, Security Protocol Information, Certificate Data
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_INFO, SPIN_CERTIFICATE_DATA);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseSimpleSrbIn(psptwb_ex, status, length, returned, "Certificate Data");
		}


		// CDB: Security Protocol In, Tape Data Encryption Security Protocol, Data Encryption Management Capabilities page
		length = CreateSecurityProtocolInSrb(psptwb_ex, SECURITY_PROTOCOL_TAPE, SPIN_TAPE_ENCRYPTION_MANAGEMENT_CAPABILITIES);
		if (length == 0) { goto Cleanup; }
		status = SendSrb(fileHandle, psptwb_ex, length, &returned);

		if (CheckStatus(fileHandle, psptwb_ex, status, returned, length))
		{
			ParseSimpleSrbIn(psptwb_ex, status, length, returned, "Data Encryption Management Capabilities");
		}
	}

Cleanup:
	if (encryptionCapabilities != NULL) {
		free(encryptionCapabilities);
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
	CloseHandle(fileHandle);
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
			PCHAR moduleName = NullPaddedNullTerminatedToString(sizeof(descriptorInfo->ModuleName),descriptorInfo->ModuleName);
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
/// Parse a pointer to a DATA_ENCRYPTION_CAPABILITIES struct
/// </summary>
/// <param name="pBuffer">A pointer to a DATA_ENCRYPTION_CAPABILITIES struct</param>
/// <param name="ppEncryptionCapabilities">A pointer to a pointer to a DATA_ENCRYPTION_CAPABILITIES struct for storing parsed data</param>
/// <param name="pAesGcmAlgorithmIndex">A pointer to a short for storing AES256-GCM algorithm index if discovered</param>
VOID
ParseDataEncryptionCapabilities(PDATA_ENCRYPTION_CAPABILITIES pBuffer, PDATA_ENCRYPTION_CAPABILITIES* ppEncryptionCapabilities, PINT16 pAesGcmAlgorithmIndex)
{
	printf("Parsing Data Encryption Capabilities page...\n");
	// Unset existing AES256-GCM algorithm index value
	*pAesGcmAlgorithmIndex = -1;
	// Allocate memory to store Data Encryption Capabilities page
	PDATA_ENCRYPTION_CAPABILITIES encryptionCapabilities = calloc(1, sizeof(DATA_ENCRYPTION_CAPABILITIES));
	// Update pointer to new struct
	*ppEncryptionCapabilities = encryptionCapabilities;
	// Copy buffer to new struct
	memcpy(encryptionCapabilities, pBuffer, sizeof(DATA_ENCRYPTION_CAPABILITIES));
	// LTO is MSB/MSb first (Big Endian), convert multi-byte field types to native byte order (Little Endian on x86-64)
	encryptionCapabilities->PageCode = ntohs(encryptionCapabilities->PageCode);
	encryptionCapabilities->PageLength = ntohs(encryptionCapabilities->PageLength);
	encryptionCapabilities->DescriptorLength = ntohs(encryptionCapabilities->DescriptorLength);
	encryptionCapabilities->UnauthKadMaxLength = ntohs(encryptionCapabilities->UnauthKadMaxLength);
	encryptionCapabilities->AuthKadMaxLength = ntohs(encryptionCapabilities->AuthKadMaxLength);
	encryptionCapabilities->KeySize = ntohs(encryptionCapabilities->KeySize);
	encryptionCapabilities->MaximumSupplementalDecryptionKeyCount = ntohs(encryptionCapabilities->MaximumSupplementalDecryptionKeyCount);
	encryptionCapabilities->AlgorithmCode = ntohl(encryptionCapabilities->AlgorithmCode);
	printf("Page length: %d bytes\n", encryptionCapabilities->PageLength);
	printf("* External Data Encryption Capable (EXTDECC): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->ExternalDataEncryptionCapable == 0b10));
	printf("* Configuration Prevented (CFG_P): %s\n", CfgPCapableStrings[encryptionCapabilities->ConfigurationPrevented]);
	printf("* Algorithm index: 0x%02X\n", encryptionCapabilities->AlgorithmIndex);
	printf("  * Descriptor Length: %d bytes\n", encryptionCapabilities->DescriptorLength);
	printf("  * Algorithm Valid For Mounted Volume (AVFMV): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->AlgorithmValidForMountedVolume));
	printf("  * Supplemental Decryption Key Capable (SDK_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->SupplementalDecryptionKeyCapable));
	printf("  * Message Authentication Code Capable (MAC_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->MacKadCapable));
	printf("  * Distinguish Encrypted Logical Block Capable (DELB_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->DistinguishEncryptedLogicalBlockCapable));
	printf("  * Decryption Capable (Decrypt_C): %s\n", EncryptionCapableStrings[encryptionCapabilities->DecryptCapable]);
	printf("  * Encryption Capable (Encrypt_C): %s\n", EncryptionCapableStrings[encryptionCapabilities->EncryptCapable]);
	printf("  * Algorithm Valid For Current Logical Position (AVFCLP): %s\n", AvfclpCapableStrings[encryptionCapabilities->AlgorithmValidForCurrentLogicalPosition]);
	printf("  * Nonce value descriptor capable (NONCE_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->NonceKadCapable == 0b11));
	printf("  * KAD Format Capable (KADF_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->KadFormatCapable));
	printf("  * Volume Contains Encrypted Logical Blocks Capable (VCELB_C): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->VolumeContainsEncryptedLogicalBlocksCapable));
	printf("  * Unauthenticated KAD Fixed Length (UKADF): %s\n", (encryptionCapabilities->UnauthKadFixedLength ? "Max UKAD Bytes" : "1 Byte to Max UKAD Bytes"));
	printf("  * Authenticated KAD Fixed Length (AKADF): %s\n", (encryptionCapabilities->AuthKadFixedLength ? "Max AKAD Bytes" : "1 Byte to Max AKAD Bytes"));
	printf("  * Maximum Unauthenticated Key-Associated Data Bytes: %d\n", encryptionCapabilities->UnauthKadMaxLength);
	printf("  * Maximum Authenticated Key-Associated Data Bytes: %d\n", encryptionCapabilities->AuthKadMaxLength);
	printf("  * Key Size: %d bytes (%d-bit)\n", encryptionCapabilities->KeySize, encryptionCapabilities->KeySize * 8);
	printf("  * Decryption KAD Capability: %s\n", DkadCapableStrings[encryptionCapabilities->DecryptionKadCapable]);
	printf("  * External Encryption Mode Control Capable (EEMC_C): %s\n", EemcCapableStrings[encryptionCapabilities->ExternalEncryptionModeControlCapable]);
	if (encryptionCapabilities->RawDecryptionModeControlCapabilities == 0x4)
	{
		printf("  * Raw Decryption Mode Control (RDMC_C): Raw decryption not allowed by default\n");
	}
	else
	{
		printf("  * Raw Decryption Mode Control (RDMC_C): 0x%02X\n", encryptionCapabilities->RawDecryptionModeControlCapabilities);
	}
	printf("  * Encryption Algorithm Records Encryption Mode (EAREM): %s\n", BOOLEAN_TO_STRING(encryptionCapabilities->EncryptionAlgorithmRecordsEncryptionMode));
	printf("  * Maximum number of supplemental decryption keys: %d\n", encryptionCapabilities->MaximumSupplementalDecryptionKeyCount);
	if (encryptionCapabilities->AlgorithmCode == SPIN_TAPE_ALGORITHM_AESGCM)
	{
		printf("  * Algorithm: AES-GCM (AES%d-GCM)\n", encryptionCapabilities->KeySize * 8);
		*pAesGcmAlgorithmIndex = encryptionCapabilities->AlgorithmIndex;
	}
	else
	{
		printf("  * Unknown Algorithm: 0x%08X\n", encryptionCapabilities->AlgorithmCode);
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
ParseDeviceServerKeyWrappingPublicKey(PDEVICE_SERVER_KEY_WRAPPING_PUBLIC_KEY deviceServerKeyWrappingPublicKey, UINT16 logicalUnitIdentifierLength, PUCHAR logicalUnitIdentifier, int* wrappedDescriptorsLength, PUCHAR* wrappedDescriptorsPtr)
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
		*wrappedDescriptorsLength = deviceServerIdentificationLength + wrappedKeyLengthDescriptorLength;
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
/// <param name="aesGcmAlgorithmIndex">The drive's encryption algorithm index for AES256-GCM</param>
VOID
ParseDataEncryptionStatus(PDATA_ENCRYPTION_STATUS dataEncryptionStatus, INT16 aesGcmAlgorithmIndex)
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
	printf("* Algorithm Index: 0x%02x (%s)\n", dataEncryptionStatus->AlgorithmIndex, dataEncryptionStatus->AlgorithmIndex == aesGcmAlgorithmIndex ? "AES256-GCM" : "Unknown");
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
/// <param name="pNextBlockStatus">A pointer to a NEXT_BLOCK_ENCRYPTION_STATUS struct</param>
/// <param name="aesGcmAlgorithmIndex">The drive's encryption algorithm index for AES256-GCM</param>
VOID
ParseNextBlockEncryptionStatus(PNEXT_BLOCK_ENCRYPTION_STATUS nextBlockStatus, INT16 aesGcmAlgorithmIndex)
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
	printf("* Encryption Algorithm: %s (0x%02x)\n", nextBlockStatus->AlgorithmIndex == aesGcmAlgorithmIndex ? "AES256-GCM" : "Unknown", nextBlockStatus->AlgorithmIndex);
	printf("* KAD Format: %s (0x%02X)\n",
		nextBlockStatus->KADFormat < NUMBER_OF_KAD_FORMAT_STRINGS
		? KadFormatStrings[nextBlockStatus->KADFormat]
		: KadFormatStrings[NUMBER_OF_KAD_FORMAT_STRINGS - 1],
		nextBlockStatus->KADFormat
	);
	printf("* KAD List Length: 0x%02x (%d bytes)\n", kadListLength, kadListLength);
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

