#pragma once

#include "Includes.h"

#include "Functions/KERNEL32.h"
#include "Functions/NT.h"
#include "Functions/Undocumented.h"
#include "Loader/Loader.h"

#ifdef _DEBUG
#ifdef UNICODE
#define WID_DBG wprintf
#else
#define WID_DBG printf
#endif
#else
#define WID_DBG ;
#endif
#define WID_HIDDEN(x) { if(CreationInfo.LoadType == LOADTYPE::DEFAULT){x} }

namespace WID
{
	extern BOOLEAN bInitialized;

	extern MODULEINFO Kernel32ModuleInfo;
	extern MODULEINFO KernelBaseModuleInfo;
	extern MODULEINFO NtdllModuleInfo;

	NTSTATUS Init();

	namespace Helper
	{
		PVOID SigScan(PCHAR StartAddress, SIZE_T Len, PCHAR Pattern, SIZE_T PatternLen);
	}
}