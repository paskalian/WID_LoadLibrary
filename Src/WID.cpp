#include "WID.h"

BOOLEAN		WID::bInitialized			= FALSE;
MODULEINFO	WID::Kernel32ModuleInfo		= {};
MODULEINFO	WID::KernelBaseModuleInfo	= {};
MODULEINFO	WID::NtdllModuleInfo		= {};

NTSTATUS WID::Init()
{
	if (!bInitialized)
	{
		// MODULE INITIALIZATION
		HMODULE Kernel32Module		= GetModuleHandle("KERNEL32.DLL");
		assert(Kernel32Module);

		HMODULE KernelBaseModule	= GetModuleHandle("KERNELBASE.DLL");
		assert(KernelBaseModule);

		HMODULE NtdllModule			= GetModuleHandle("NTDLL.DLL");
		assert(NtdllModule);

		(GetModuleInformation(GetCurrentProcess(), Kernel32Module,		&Kernel32ModuleInfo,	sizeof(MODULEINFO)),	assert(Kernel32ModuleInfo.lpBaseOfDll));
		(GetModuleInformation(GetCurrentProcess(), KernelBaseModule,	&KernelBaseModuleInfo,	sizeof(MODULEINFO)),	assert(KernelBaseModuleInfo.lpBaseOfDll));
		(GetModuleInformation(GetCurrentProcess(), NtdllModule,			&NtdllModuleInfo,		sizeof(MODULEINFO)),	assert(NtdllModuleInfo.lpBaseOfDll));

		// KERNEL32
		(Basep8BitStringToDynamicUnicodeString	= (tBasep8BitStringToDynamicUnicodeString)GetProcAddress(Kernel32Module, "Basep8BitStringToDynamicUnicodeString")	,assert(Basep8BitStringToDynamicUnicodeString));
		(BaseSetLastNTError						= (tBaseSetLastNTError)GetProcAddress(Kernel32Module, "BaseSetLastNTError")											,assert(BaseSetLastNTError));

		// NTDLL
		(LdrpMainThreadToken					= (HANDLE*)							(NtdllModule + 0x1842C8)								,assert(LdrpMainThreadToken));
		(LdrInitState							= (DWORD*)							(NtdllModule + 0x185220)								,assert(LdrInitState));

		(NtOpenThreadToken						= (tNtOpenThreadToken)				GetProcAddress(NtdllModule, "NtOpenThreadToken")		,assert(NtOpenThreadToken));
		(NtClose								= (tNtClose)						GetProcAddress(NtdllModule, "NtClose")					,assert(NtClose));
		(RtlAllocateHeap						= (tRtlAllocateHeap)				GetProcAddress(NtdllModule, "RtlAllocateHeap")			,assert(RtlAllocateHeap));
		(RtlFreeHeap							= (tRtlFreeHeap)					GetProcAddress(NtdllModule, "RtlFreeHeap")				,assert(RtlFreeHeap));
		(RtlFreeUnicodeString					= (tRtlFreeUnicodeString)			GetProcAddress(NtdllModule, "RtlFreeUnicodeString")		,assert(RtlFreeUnicodeString));
		(LdrGetDllPath							= (tLdrGetDllPath)					GetProcAddress(NtdllModule, "LdrGetDllPath")			,assert(LdrGetDllPath));
		(RtlReleasePath							= (tRtlReleasePath)					GetProcAddress(NtdllModule, "RtlReleasePath")			,assert(RtlReleasePath));
		(RtlInitUnicodeStringEx					= (tRtlInitUnicodeStringEx)			GetProcAddress(NtdllModule, "RtlInitUnicodeStringEx")	,assert(RtlInitUnicodeStringEx));
		// I don't think the signatures will ever change, you can go with the offsets though.
		(LdrpLogInternal						= (tLdrpLogInternal)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_INTERNAL_PATTERN,					strlen(LDRP_LOG_INTERNAL_PATTERN))					,assert(LdrpLogInternal));
		(LdrpInitializeDllPath					= (tLdrpInitializeDllPath)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INITIALIZE_DLLPATH_PATTERN,			strlen(LDRP_INITIALIZE_DLLPATH_PATTERN))			,assert(LdrpInitializeDllPath));
		(LdrpDereferenceModule					= (tLdrpDereferenceModule)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DEREFERENCE_MODULE_PATTERN,			strlen(LDRP_DEREFERENCE_MODULE_PATTERN))			,assert(LdrpDereferenceModule));
		(LdrpLogDllState						= (tLdrpLogDllState)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DLLSTATE_PATTERN,					strlen(LDRP_LOG_DLLSTATE_PATTERN))					,assert(LdrpLogDllState));
		(LdrpPreprocessDllName					= (tLdrpPreprocessDllName)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PREPROCESS_DLLNAME_PATTERN,			strlen(LDRP_PREPROCESS_DLLNAME_PATTERN))			,assert(LdrpPreprocessDllName));
		(LdrpFastpthReloadedDll					= (tLdrpFastpthReloadedDll)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FASTPTH_RELOADED_DLL_PATTERN,			strlen(LDRP_FASTPTH_RELOADED_DLL_PATTERN))			,assert(LdrpFastpthReloadedDll));
		(LdrpDrainWorkQueue						= (tLdrpDrainWorkQueue)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DRAIN_WORKQUEUE_PATTERN,				strlen(LDRP_DRAIN_WORKQUEUE_PATTERN))				,assert(LdrpDrainWorkQueue));
		(LdrpFindLoadedDllByHandle				= (tLdrpFindLoadedDllByHandle)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN,		strlen(LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN))		,assert(LdrpFindLoadedDllByHandle));
		(LdrpDropLastInProgressCount			= (tLdrpDropLastInProgressCount)	Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN,	strlen(LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN))		,assert(LdrpDropLastInProgressCount));
		(LdrpQueryCurrentPatch					= (tLdrpQueryCurrentPatch)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_QUERY_CURRENT_PATCH_PATTERN,			strlen(LDRP_QUERY_CURRENT_PATCH_PATTERN))			,assert(LdrpQueryCurrentPatch));
		(LdrpUndoPatchImage						= (tLdrpUndoPatchImage)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_UNDO_PATCH_IMAGE_PATTERN,				strlen(LDRP_UNDO_PATCH_IMAGE_PATTERN))				,assert(LdrpUndoPatchImage));
		(LdrpDetectDetour						= (tLdrpDetectDetour)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DETECT_DETOUR_PATTERN,				strlen(LDRP_DETECT_DETOUR_PATTERN))					,assert(LdrpDetectDetour));
		(LdrpFindOrPrepareLoadingModule			= (tLdrpFindOrPrepareLoadingModule)	Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN,	strlen(LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN))	,assert(LdrpFindOrPrepareLoadingModule));
		(LdrpFreeLoadContext					= (tLdrpFreeLoadContext)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOAD_CONTEXT_PATTERN,			strlen(LDRP_FREE_LOAD_CONTEXT_PATTERN))				,assert(LdrpFreeLoadContext));
		(LdrpCondenseGraph						= (tLdrpCondenseGraph)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CONDENSE_GRAPH_PATTERN,				strlen(LDRP_CONDENSE_GRAPH_PATTERN))				,assert(LdrpCondenseGraph));
		(LdrpBuildForwarderLink					= (tLdrpBuildForwarderLink)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_BUILD_FORWARDER_LINK_PATTERN,			strlen(LDRP_BUILD_FORWARDER_LINK_PATTERN))			,assert(LdrpBuildForwarderLink));
		(LdrpPinModule							= (tLdrpPinModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PIN_MODULE_PATTERN,					strlen(LDRP_PIN_MODULE_PATTERN))					,assert(LdrpPinModule));
		(LdrpApplyPatchImage					= (tLdrpApplyPatchImage)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APPLY_PATCH_IMAGE_PATTERN,			strlen(LDRP_APPLY_PATCH_IMAGE_PATTERN))				,assert(LdrpApplyPatchImage));
		(LdrpFreeLoadContextOfNode				= (tLdrpFreeLoadContextOfNode)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOADCONTEXT_NODE_PATTERN,		strlen(LDRP_FREE_LOADCONTEXT_NODE_PATTERN))			,assert(LdrpFreeLoadContextOfNode));
		(LdrpDecrementModuleLoadCountEx			= (tLdrpDecrementModuleLoadCountEx)	Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN,	strlen(LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN))	,assert(LdrpDecrementModuleLoadCountEx));

		WID_DBG( printf("[WID] >> Initialized.\n"); )

		bInitialized = TRUE;
		return STATUS_SUCCESS;
	}
	WID_DBG(printf("[WID] >> Already initialized.\n"); )
	return STATUS_SUCCESS;
}

PVOID WID::Helper::SigScan(PCHAR StartAddress, SIZE_T Len, PCHAR Pattern, SIZE_T PatternLen)
{
	bool Found = TRUE;
	for (int i1 = 0; i1 < Len; i1++)
	{
		Found = TRUE;
		for (int i2 = 0; i2 < PatternLen; i2++)
		{
			if (Pattern[i2] != 0 && StartAddress[i1 + i2] != Pattern[i2])
			{
				Found = FALSE;
				break;
			}
		}

		if (Found)
			return StartAddress + i1;
	}

	return nullptr;
}