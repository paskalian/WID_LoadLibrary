#pragma once

#include "..\Includes.h"
#include "Undocumented.h"

extern ULONG* KernelBaseGlobalData;

typedef BOOLEAN(WINAPI* tBasep8BitStringToDynamicUnicodeString)(PUNICODE_STRING pConvertedStr, LPCSTR pszAnsiStr);
extern tBasep8BitStringToDynamicUnicodeString Basep8BitStringToDynamicUnicodeString;

typedef DWORD(WINAPI* tBaseSetLastNTError)(IN NTSTATUS Status);
extern tBaseSetLastNTError BaseSetLastNTError;

// Signatured
#define BASEP_LLASDATAFILE_INTERNAL_PATTERN "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x10\xFF\xFF\xFF"
typedef NTSTATUS(__fastcall* tBasepLoadLibraryAsDataFileInternal)(PUNICODE_STRING DllName, PWSTR Path, PWSTR Unknown, DWORD dwFlags, HMODULE* pBaseOfLoadedModule);
extern tBasepLoadLibraryAsDataFileInternal BasepLoadLibraryAsDataFileInternal;