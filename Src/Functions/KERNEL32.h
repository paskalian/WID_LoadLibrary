#pragma once

#include "..\Includes.h"
#include "Undocumented.h"

extern ULONG* KernelBaseGlobalData;

typedef BOOLEAN(WINAPI* tBasep8BitStringToDynamicUnicodeString)(PUNICODE_STRING pConvertedStr, LPCSTR pszAnsiStr);
extern tBasep8BitStringToDynamicUnicodeString Basep8BitStringToDynamicUnicodeString;

typedef DWORD(WINAPI* tBaseSetLastNTError)(IN NTSTATUS Status);
extern tBaseSetLastNTError BaseSetLastNTError;