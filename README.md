# RDP-THIEF
RDP THIEF - inject dll to mstsc process and steal user credentials.

## Requierments:
Microsoft Detours Library - https://github.com/microsoft/Detours

**Compile:**
1. Unzip source code, open command line and enter to source directory
2. SET DETOURS_TARGET_PROCESSOR=X64
3. C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat
4. NMAKE

Add detours.lib to Linker additional libraries.

**Hooked Functions:**
- CredIsMarshaledCredentialW
- CredReadW
- CryptProtectMemory <br>
  microsoft did a trick, the address to pointer not as describe in dpapi.h, need to find function address when loading dll.
