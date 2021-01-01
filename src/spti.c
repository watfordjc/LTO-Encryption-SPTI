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

VOID
__cdecl
main(
    _In_ int argc,
    _In_z_ char *argv[]
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
          returned = 0,
          sectorSize = 512;

    if ((argc < 2) || (argc > 3)) {
       printf("Usage:  %s <port-name> [-mode]\n", argv[0] );
       printf("Examples:\n");
       printf("    spti g:       (open the disk class driver in SHARED READ/WRITE mode)\n");
       printf("    spti Scsi2:   (open the miniport driver for the 3rd host adapter)\n");
       printf("    spti Tape0 w  (open the tape class driver in SHARED WRITE mode)\n");
       printf("    spti i: c     (open the CD-ROM class driver in SHARED READ mode)\n");
       return;
    }

    StringCbPrintf(string, sizeof(string), "\\\\.\\%s", argv[1]);

    shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;  // default
    accessMode = GENERIC_WRITE | GENERIC_READ;       // default

    if (argc == 3) {

        switch(tolower(argv[2][0])) {
            case 'r':
                shareMode = FILE_SHARE_READ;
                break;

            case 'w':
                shareMode = FILE_SHARE_WRITE;
                break;

            case 'c':
                shareMode = FILE_SHARE_READ;
                sectorSize = 2048;
                break;

            default:
                printf("%s is an invalid mode.\n", argv[2]);
                puts("\tr = read");
                puts("\tw = write");
                puts("\tc = read CD (2048 byte sector mode)");
                return;
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
    if (!status ) {
        errorCode = GetLastError();
        printf("Error getting device and/or adapter properties; "
               "error was %d\n", errorCode);
        PrintError(errorCode);
        CloseHandle(fileHandle);
        return;
    }

    printf("\n"
           "            *****     Detected Alignment Mask    *****\n"
           "            *****             was %08x       *****\n\n\n",
           alignmentMask);

    if (storageBusType == BusTypeSas)
    {
        printf("Using SAS.\n\n");
    }
    else
    {
        printf("Using %s - only tested with SAS.\n\n", BusTypeStrings[storageBusType]);
    }

    //
    // Send SCSI Pass Through
    //



    if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
    {
        printf("Using STORAGE_REQUEST_BLOCK.\n\n");
        length = ResetSRB(&sptwb_ex, CDB12GENERIC_LENGTH);
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
            PSUPPORTED_SECURITY_PROTOCOLS_PARAMETER_DATA data = (void *)sptwb_ex.ucDataBuf;
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
                case SECURITY_PROTOCOL_TAPE:
                    securityProtocol = "Tape Data Encryption (SSC-3)";
                    capTapeEncryption = TRUE;
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
        length = ResetSRB(&sptwb_ex, CDB12GENERIC_LENGTH);
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
            int algorithmIndex = sptwb_ex.ucDataBuf[20];
            printf("Algorithm index: 0x%02X\n", algorithmIndex);
            int descriptorLength = sptwb_ex.ucDataBuf[22] << 8 | sptwb_ex.ucDataBuf[23];
            printf("Descriptor Length: %d bytes\n", descriptorLength);
            printf("Algorithm Valid For Mounted Volume (AVFMV): %s\n", (sptwb_ex.ucDataBuf[24] & (0b10000000 >> 7)) == 0b1 ? "True" : "False");
            int capDecrypt = sptwb_ex.ucDataBuf[24] & 0b00001100 >> 2;
            switch (capDecrypt)
            {
            case 0b10:
                description = "Hardware";
                break;
            case 0b11:
                description = "CFG_P";
                break;
            default:
                description = "Unknown";
                break;
            }
            printf("Decryption Capable (Decrypt_C): %s\n", description);
            int capEncrypt = sptwb_ex.ucDataBuf[24] & 0b00000011;
            switch (capEncrypt)
            {
            case 0b10:
                description = "Hardware";
                break;
            case 0b11:
                description = "CFG_P";
                break;
            default:
                description = "Unknown";
                break;
            }
            printf("Encryption Capable (Encrypt_C): %s\n", description);
            int capAvfclp = sptwb_ex.ucDataBuf[25] & 0b11000000 >> 6;
            switch (capAvfclp)
            {
            case 0b00:
                description = "No tape loaded";
                break;
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
            printf("Algorithm Valid For Current Logical Position (AVFCLP): %s\n", description);
            int maxUnauthKeyBytes = sptwb_ex.ucDataBuf[26] << 8 | sptwb_ex.ucDataBuf[27];
            printf("Maximum Unauthenticated Key-Associated Data Bytes: %d\n", maxUnauthKeyBytes);
            int maxAuthKeyBytes = sptwb_ex.ucDataBuf[28] << 8 | sptwb_ex.ucDataBuf[29];
            printf("Maximum Authenticated Key-Associated Data Bytes: %d\n", maxAuthKeyBytes);
            int keySize = sptwb_ex.ucDataBuf[30] << 8 | sptwb_ex.ucDataBuf[31];
            printf("Key Size: %d bytes (%d-bit)\n", keySize, keySize * 8);
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
            if (algorithmCode == 0x00010014)
            {
                printf("Algorithm: AES-GCM (AES%d-GCM)\n", keySize * 8);
            }
            else
            {
                printf("Unknown Algorithm: 0x%08X\n", algorithmCode);
            }

            printf("\n\n");
        }

      //  PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
    }

    BOOL capRfc3394 = FALSE;
    if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
    {
        length = ResetSRB(&sptwb_ex, CDB12GENERIC_LENGTH);
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
                switch (sptwb_ex.ucDataBuf[4+i])
                {
                case SPIN_TAPE_KEY_FORMAT_PLAIN:
                    description = "Plain-text";
                    break;
                case SPIN_TAPE_KEY_FORMAT_WRAPPED:
                    description = "Wrapped/RFC 3394";
                    capRfc3394 = TRUE;
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

    if (capRfc3394)
    {
        printf("This device supports RFC 3394 AES Key-Wrapping.\n\n");
    }
    else
    {
        fprintf(stderr, "This device doesn't support RFC 3394 AES Key-Wrapping.\n");
    }

    // If the device supports AES key wrapping (RFC 3394), try to obtain the RSA-2048 public key
    if (capRfc3394 && srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
    {
        length = ResetSRB(&sptwb_ex, CDB12GENERIC_LENGTH);
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
            if (publicKeyType == SPIN_TAPE_PUBKEY_TYPE_RSA)
            {
                printf("Public Key Type: RSA-2048\n");
            }
            long publicKeyFormat = sptwb_ex.ucDataBuf[8] << 24 | sptwb_ex.ucDataBuf[9] << 16 | sptwb_ex.ucDataBuf[10] << 8 | sptwb_ex.ucDataBuf[11];
            if (publicKeyFormat == SPIN_TAPE_PUBKEY_FORMAT_RSA)
            {
                printf("Public Key Format: RSA-2048\n");
            }
            int publicKeyLength = sptwb_ex.ucDataBuf[12] << 8 | sptwb_ex.ucDataBuf[13];
            printf("Public Key length: %d bytes\n", publicKeyLength);
            if (publicKeyType != SPIN_TAPE_PUBKEY_TYPE_RSA || publicKeyFormat != SPIN_TAPE_PUBKEY_FORMAT_RSA || publicKeyLength != 512)
            {
                fprintf(stderr, "RFC 3394 public key is not expected type/format/length.\n");
                CloseHandle(fileHandle);
                return;
            }
            char publicKeyModulus[256] = { '\0' };
            char publicKeyExponent[256] = { '\0' };
            BOOL leadingZeros = TRUE;
            int modulusOffset = 0;
            memcpy(&publicKeyModulus, &sptwb_ex.ucDataBuf[14], 256);
            for (int i = 0; i < 256; i++)
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
            leadingZeros = TRUE;
            int exponentOffset = 0;
            memcpy(&publicKeyExponent, &sptwb_ex.ucDataBuf[14 + 256], 256);
            for (int i = 0; i < 256; i++)
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
            // Convert the public key to hex-encoded DER if the following are true:
            // 1) The modulus is 256 bytes (2048-bit),
            // 2) The exponent is 3 bytes long (99.5% of RSA keys use e=65537=0x010001)
            // NB: A 2040-bit (255 byte) modulus fails to meet these conditions - DER forbids integers starting 0x0000
            if (modulusOffset == 0 && exponentOffset == (256 - 3))
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
            }

            printf("\n\n");
        }

      //  PrintDataBuffer(sptwb_ex.ucDataBuf, sptwb_ex.spt.DataInTransferLength);
    }

    if (srbType == SRB_TYPE_STORAGE_REQUEST_BLOCK)
    {
        length = ResetSRB(&sptwb_ex, CDB12GENERIC_LENGTH);
        sptwb_ex.spt.Cdb[0] = SCSIOP_SECURITY_PROTOCOL_IN;
        sptwb_ex.spt.Cdb[1] = SECURITY_PROTOCOL_INFO; // security protocol information
        sptwb_ex.spt.Cdb[3] = SPIN_CERTIFICATE_DATA; // certificate data
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
        printf("Parsing Certificate data...\n");
        int certificateLength = sptwb_ex.ucDataBuf[2] << 8 | sptwb_ex.ucDataBuf[3];
        printf("Certificate length: %d bytes\n", certificateLength);
    }

    /*
    * Unauthenticated Key-Associated Data (KAD) and Authenticated Key-Associated Data (AKAD)
    *
    * This is used to store data with every record written that can be used to ascertain which key was used to encrypt that record.
    *
    *
    */


    if (pUnAlignedBuffer != NULL) {
        free(pUnAlignedBuffer);
    }
    CloseHandle(fileHandle);
}

int
ResetSRB(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex, int cdbLength)
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
    psptwb_ex->StorAddress.Target = 1;
    psptwb_ex->StorAddress.Lun = 0;
    psptwb_ex->spt.SenseInfoOffset =
        offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucSenseBuf);
    psptwb_ex->spt.DataOutBufferOffset = 0;
    psptwb_ex->spt.DataInBufferOffset =
        offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf);
    return offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS_EX, ucDataBuf) +
        psptwb_ex->spt.DataInTransferLength;
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
    } else {
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
          printf(" %03X  ",Cnt);
          }
       printf("%02X  ", DataBuffer[Cnt]);
       if ((Cnt+1) % 8 == 0) {
          printf(" ");
          }
       if ((Cnt+1) % 16 == 0) {
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
    } else {
        busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS-1];
    }

    // subtract one page, as transfers do not always start on a page boundary
    if (AdapterDescriptor->MaximumPhysicalPages > 1) {
        trueMaximumTransferLength = AdapterDescriptor->MaximumPhysicalPages - 1;
    } else {
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
    } else {
        busType = BusTypeStrings[NUMBER_OF_BUS_TYPE_STRINGS-1];
    }

    if ((DeviceDescriptor->ProductIdOffset != 0) &&
        (DeviceDescriptor->ProductIdOffset != -1)) {
        productId        = (LPCSTR)(DeviceDescriptor);
        productId       += (ULONG_PTR)DeviceDescriptor->ProductIdOffset;
    }
    if ((DeviceDescriptor->VendorIdOffset != 0) &&
        (DeviceDescriptor->VendorIdOffset != -1)) {
        vendorId         = (LPCSTR)(DeviceDescriptor);
        vendorId        += (ULONG_PTR)DeviceDescriptor->VendorIdOffset;
    }
    if ((DeviceDescriptor->ProductRevisionOffset != 0) &&
        (DeviceDescriptor->ProductRevisionOffset != -1)) {
        productRevision  = (LPCSTR)(DeviceDescriptor);
        productRevision += (ULONG_PTR)DeviceDescriptor->ProductRevisionOffset;
    }
    if ((DeviceDescriptor->SerialNumberOffset != 0) &&
        (DeviceDescriptor->SerialNumberOffset != -1)) {
        serialNumber     = (LPCSTR)(DeviceDescriptor);
        serialNumber    += (ULONG_PTR)DeviceDescriptor->SerialNumberOffset;
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

_Success_(return != NULL)
_Post_writable_byte_size_(size)
PUCHAR
AllocateAlignedBuffer(
    _In_ ULONG size,
    _In_ ULONG AlignmentMask,
    _Outptr_result_maybenull_ PUCHAR *pUnAlignedBuffer)
{
    PUCHAR ptr;

    // NOTE: This routine does not allow for a way to free
    //       memory.  This is an excercise left for the reader.
    UINT_PTR    align64 = (UINT_PTR)AlignmentMask;

    if (AlignmentMask == 0) {
       ptr = malloc(size);
       *pUnAlignedBuffer = ptr;
    } else {
       ULONG totalSize;

       (void) ULongAdd(size, AlignmentMask, &totalSize);
       ptr = malloc(totalSize);
       *pUnAlignedBuffer = ptr;
       ptr = (PUCHAR)(((UINT_PTR)ptr + align64) & ~align64);
    }

    if (ptr == NULL) {
       printf("Memory allocation error.  Terminating program\n");
       exit(1);
    } else {
       return ptr;
    }
}

VOID
PrintStatusResults(
    BOOL status,DWORD returned,PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb,
    ULONG length)
{
    ULONG errorCode;

    if (!status ) {
       printf( "Error: %d  ",
          errorCode = GetLastError() );
       PrintError(errorCode);
       return;
       }
    if (psptwb->spt.ScsiStatus) {
       PrintSenseInfo(psptwb);
       return;
       }
    else {
       printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
          psptwb->spt.ScsiStatus,returned);
       printf("Data buffer length: %Xh\n\n\n",
          psptwb->spt.DataTransferLength);
       PrintDataBuffer((PUCHAR)psptwb,length);
       }
}

VOID
PrintSenseInfo(PSCSI_PASS_THROUGH_WITH_BUFFERS psptwb)
{
    UCHAR i;

    printf("Scsi status: %02Xh\n\n",psptwb->spt.ScsiStatus);
    if (psptwb->spt.SenseInfoLength == 0) {
       return;
       }
    printf("Sense Info -- consult SCSI spec for details\n");
    printf("-------------------------------------------------------------\n");
    for (i=0; i < psptwb->spt.SenseInfoLength; i++) {
       printf("%02X ",psptwb->ucSenseBuf[i]);
       }
    printf("\n\n");
}

VOID
PrintStatusResultsEx(
    BOOL status,DWORD returned,PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex,
    ULONG length)
{
    ULONG errorCode;

    if (!status ) {
       printf( "Error: %d  ",
          errorCode = GetLastError() );
       PrintError(errorCode);
       return;
       }
    if (psptwb_ex->spt.ScsiStatus) {
       PrintSenseInfoEx(psptwb_ex);
       return;
       }
    else {
       printf("Scsi status: %02Xh, Bytes returned: %Xh, ",
          psptwb_ex->spt.ScsiStatus,returned);
       printf("DataOut buffer length: %Xh\n"
              "DataIn buffer length: %Xh\n\n\n",
          psptwb_ex->spt.DataOutTransferLength,
          psptwb_ex->spt.DataInTransferLength);
       PrintDataBuffer((PUCHAR)psptwb_ex,length);
       }
}

VOID
PrintSenseInfoEx(PSCSI_PASS_THROUGH_WITH_BUFFERS_EX psptwb_ex)
{
    ULONG i;

    printf("Scsi status: %02Xh\n\n",psptwb_ex->spt.ScsiStatus);
    if (psptwb_ex->spt.SenseInfoLength == 0) {
       return;
       }
    printf("Sense Info -- consult SCSI spec for details\n");
    printf("-------------------------------------------------------------\n");
    for (i=0; i < psptwb_ex->spt.SenseInfoLength; i++) {
       printf("%02X ",psptwb_ex->ucSenseBuf[i]);
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
    STORAGE_DESCRIPTOR_HEADER header = {0};

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
    for (i=0;i<4;i++) {

        PVOID buffer = NULL;
        ULONG bufferSize = 0;
        ULONG returnedData;

        STORAGE_PROPERTY_QUERY query = {0};

        switch(i) {
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
                } else if (GetLastError() == ERROR_INVALID_FUNCTION) {
                    // this is also ok, the property DNE
                } else if (GetLastError() == ERROR_NOT_SUPPORTED) {
                    // this is also ok, the property DNE
                } else {
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
    } else {
        PrintAdapterDescriptor(adapterDescriptor);
        *AlignmentMask = adapterDescriptor->AlignmentMask;
        *SrbType = adapterDescriptor->SrbType;
    }

    if (deviceDescriptor == NULL) {
        printf("   ***** No device descriptor supported on the device  *****\n");
    } else {
        PrintDeviceDescriptor(deviceDescriptor);
        *StorageBusType = deviceDescriptor->BusType;
    }

    failed = FALSE;

Cleanup:
    if (adapterDescriptor != NULL) {
        LocalFree( adapterDescriptor );
    }
    if (deviceDescriptor != NULL) {
        LocalFree( deviceDescriptor );
    }
    return (!failed);

}

