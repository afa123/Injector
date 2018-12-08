#pragma once

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFileName);
using f_GetProcAddress = UINT_PTR(WINAPI*)(HINSTANCE hModule, const char* lpProcName); // normally returns a far pointer but to make it easier a uint_ptr is returned here, fix it later
using f_NtCreateThreadEx = NTSTATUS(__stdcall*)(HANDLE* pHandle, ACCESS_MASK desiredAccess, void* pAttribute, HANDLE hProc, void* pFunction, void* pArg, ULONG flags, SIZE_T zeroBits, SIZE_T stackSize, SIZE_T maxStackSize, void* pAttriListOut);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	HINSTANCE hMod;
};

bool ManualMap(HANDLE hProc, const char* szDllFile);
void __stdcall shellcode(MANUAL_MAPPING_DATA*);
BYTE* getFile(const char* szDllFile);
