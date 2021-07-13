# LTO-Encryption-SPTI

This is a utility based on the [SCSI Pass-Through Interface Tool](https://github.com/watfordjc/SCSI_Pass_Through_Interface_Tool) GitHub template, a templated version of the [SCSI Pass-Through Interface Tool driver sample](https://github.com/microsoft/Windows-driver-samples/tree/master/storage/tools/spti) from the Windows Driver Kit (WDK) driver samples.

LTO-Encryption-SPTI is part of the [**Data Backups and Archiving GitHub Project**](https://github.com/users/watfordjc/projects/2).

The purpose of this tool will be to pass symmetric encryption keys to an LTO drive using SPTI.

**This repository does not yet contain complete software.**

## spti Parameters

The current commit of spti.exe only accepts arguments in a particular order.

```spti drive key kad```

* spti: executable name
  * If no parameters are supplied, usage information is displayed and installed tape drives are listed.
* drive:
  * drive name (e.g. **tape0**)
  * device path (e.g. **"\\\\?\scsi#sequential&ven_hp&prod_ultrium_6-scsi#..."**)
* key: *optional*:
  * **none** to clear keys and disable encryption and decryption.
  * **weak** for a hard-coded very weak key set using plain key format (for testing encryption support); ```0x00``` key format.
  * **ABCD...** a 64 character long hex string for an AES-256 key; ```0x00``` key format.
  * **ABCD...** a 512 character long hex string for an RSA-2048 wrapped AES-256 key; ```0x02``` key format.
* kad: *optional*:
  * **TestKAD** use the Key-Associated Data (KAD) ASCII value of **TestKAD** for blocks written to a tape.
    * This is currently limited to ASCII characters and AKAD (authenticated KAD) drive and tape limitations.
    * For LTO-5 and LTO-6, ```kad``` must either be (a) 60 characters or fewer, or (b) exactly 60 characters. For LTO-4, that becomes 12 characters. The program currently prints an error message stating the drive/tape AKAD limits if the command line parameter doesn't meet them.

## Licensing

Per the Microsoft Public License, the source code for this repository is licenced MS-PL. Any object/executable code (Releases) are also made available under the MIT License.
