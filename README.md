# RDP-THIEF
Inject dll to remote desktop process (mstsc.exe) and steal user credentials.

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
  Microsoft try to hide it, The address to the function is dynamic, you need to find it yourself.
  
**References:**<br>
https://github.com/0x09AL/RdpThief<br>
https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/
  
