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
		// Variables
		(LdrpPolicyBits							= (DWORD*)								((PCHAR)NtdllModule + 0x181694)								,assert(LdrpPolicyBits));
		(LdrpMainThreadToken					= (HANDLE*)								((PCHAR)NtdllModule + 0x1842C8)								,assert(LdrpMainThreadToken));
		(LdrInitState							= (DWORD*)								((PCHAR)NtdllModule + 0x185220)								,assert(LdrInitState));
		(LoadFailure							= (DWORD*)								((PCHAR)NtdllModule + 0x135CA0)								,assert(LoadFailure));
		(LdrpWorkQueueLock						= (PRTL_CRITICAL_SECTION)				((PCHAR)NtdllModule + 0x184280)								,assert(LdrpWorkQueueLock));
		(LdrpWorkInProgress						= (DWORD*)								((PCHAR)NtdllModule + 0x1842A8)								,assert(LdrpWorkInProgress));
		(LdrpWorkQueue							= (LIST_ENTRY**)						((PCHAR)NtdllModule + 0x1842B0)								,assert(LdrpWorkQueue));
		(LdrpWorkCompleteEvent					= (PHANDLE)								((PCHAR)NtdllModule + 0x184260)								,assert(LdrpWorkCompleteEvent));
		(LdrpUseImpersonatedDeviceMap			= (DWORD*)								((PCHAR)NtdllModule + 0x184350)								,assert(LdrpUseImpersonatedDeviceMap));
		(LdrpAuditIntegrityContinuity			= (DWORD*)								((PCHAR)NtdllModule + 0x184328)								,assert(LdrpAuditIntegrityContinuity));
		(LdrpEnforceIntegrityContinuity			= (DWORD*)								((PCHAR)NtdllModule + 0x1842D8)								,assert(LdrpEnforceIntegrityContinuity));
		(LdrpFatalHardErrorCount				= (DWORD*)								((PCHAR)NtdllModule + 0x183EE8)								,assert(LdrpFatalHardErrorCount));
		(UseWOW64								= (DWORD*)								((PCHAR)NtdllModule + 0x1843E8)								,assert(UseWOW64));
		(LdrpModuleDatatableLock				= (PRTL_SRWLOCK)						((PCHAR)NtdllModule + 0x184D40)								,assert(LdrpModuleDatatableLock));
		(qword_17E238							= (PHANDLE)								((PCHAR)NtdllModule + 0x17E238)								,assert(qword_17E238));
		(LdrpImageEntry							= (LDR_DATA_TABLE_ENTRY**)				((PCHAR)NtdllModule + 0x183F88)								,assert(LdrpImageEntry));
		(LdrpKernel32DllName					= (PUNICODE_STRING)						((PCHAR)NtdllModule + 0x1311C0)								,assert(LdrpKernel32DllName));
		(LdrpAppHeaders							= (UINT_PTR*)							((PCHAR)NtdllModule + 0x1842D0)								,assert(LdrpAppHeaders));
		(LdrpLargePageDllKeyHandle				= (PHANDLE)								((PCHAR)NtdllModule + 0x183EE0)								,assert(LdrpLargePageDllKeyHandle));
		(LdrpLockMemoryPrivilege				= (ULONG**)								((PCHAR)NtdllModule + 0x14DAC0)								,assert(LdrpLockMemoryPrivilege));
		(LdrpMaximumUserModeAddress				= (ULONG64*)							((PCHAR)NtdllModule + 0x199280)								,assert(LdrpMaximumUserModeAddress));
		(LdrpMapAndSnapWork						= (UINT_PTR*)							((PCHAR)NtdllModule + 0x184238)								,assert(LdrpMapAndSnapWork));

		// Exported functions
		(NtOpenThreadToken						= (tNtOpenThreadToken)					GetProcAddress(NtdllModule, "NtOpenThreadToken")			,assert(NtOpenThreadToken));
		(NtClose								= (tNtClose)							GetProcAddress(NtdllModule, "NtClose")						,assert(NtClose));
		(RtlAllocateHeap						= (tRtlAllocateHeap)					GetProcAddress(NtdllModule, "RtlAllocateHeap")				,assert(RtlAllocateHeap));
		(RtlFreeHeap							= (tRtlFreeHeap)						GetProcAddress(NtdllModule, "RtlFreeHeap")					,assert(RtlFreeHeap));
		(LdrGetDllPath							= (tLdrGetDllPath)						GetProcAddress(NtdllModule, "LdrGetDllPath")				,assert(LdrGetDllPath));
		(RtlReleasePath							= (tRtlReleasePath)						GetProcAddress(NtdllModule, "RtlReleasePath")				,assert(RtlReleasePath));
		(RtlInitUnicodeStringEx					= (tRtlInitUnicodeStringEx)				GetProcAddress(NtdllModule, "RtlInitUnicodeStringEx")		,assert(RtlInitUnicodeStringEx));
		(RtlEnterCriticalSection				= (tRtlEnterCriticalSection)			GetProcAddress(NtdllModule, "RtlEnterCriticalSection")		,assert(RtlEnterCriticalSection));
		(RtlLeaveCriticalSection				= (tRtlLeaveCriticalSection)			GetProcAddress(NtdllModule, "RtlLeaveCriticalSection")		,assert(RtlLeaveCriticalSection));
		(ZwSetEvent								= (tZwSetEvent)							GetProcAddress(NtdllModule, "ZwSetEvent")					,assert(ZwSetEvent));
		(NtOpenFile								= (tNtOpenFile)							GetProcAddress(NtdllModule, "NtOpenFile")					,assert(NtOpenFile));
		(LdrAppxHandleIntegrityFailure			= (tLdrAppxHandleIntegrityFailure)		GetProcAddress(NtdllModule, "LdrAppxHandleIntegrityFailure"),assert(LdrAppxHandleIntegrityFailure));
		(NtRaiseHardError						= (tNtRaiseHardError)					GetProcAddress(NtdllModule, "NtRaiseHardError")				,assert(NtRaiseHardError));
		(RtlImageNtHeaderEx						= (tRtlImageNtHeaderEx)					GetProcAddress(NtdllModule, "RtlImageNtHeaderEx")			,assert(RtlImageNtHeaderEx));
		(RtlAcquireSRWLockExclusive				= (tRtlAcquireSRWLockExclusive)			GetProcAddress(NtdllModule, "RtlAcquireSRWLockExclusive")	,assert(RtlAcquireSRWLockExclusive));
		(RtlReleaseSRWLockExclusive				= (tRtlReleaseSRWLockExclusive)			GetProcAddress(NtdllModule, "RtlReleaseSRWLockExclusive")	,assert(RtlReleaseSRWLockExclusive));
		(RtlEqualUnicodeString					= (tRtlEqualUnicodeString)				GetProcAddress(NtdllModule, "RtlEqualUnicodeString")		,assert(RtlEqualUnicodeString));
		(RtlAcquirePrivilege					= (tRtlAcquirePrivilege)				GetProcAddress(NtdllModule, "RtlAcquirePrivilege")			,assert(RtlAcquirePrivilege));
		(RtlReleasePrivilege					= (tRtlReleasePrivilege)				GetProcAddress(NtdllModule, "RtlReleasePrivilege")			,assert(RtlReleasePrivilege));
		(RtlCompareUnicodeStrings				= (tRtlCompareUnicodeStrings)			GetProcAddress(NtdllModule, "RtlCompareUnicodeStrings")		,assert(RtlCompareUnicodeStrings));
		(RtlImageNtHeader						= (tRtlImageNtHeader)					GetProcAddress(NtdllModule, "RtlImageNtHeader")				,assert(RtlImageNtHeader));

		// Signatured.
		// I don't think the signatures will ever change, you can go with the offsets though.
		(LdrpLogInternal							= (tLdrpLogInternal)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_INTERNAL_PATTERN,					strlen(LDRP_LOG_INTERNAL_PATTERN))					,assert(LdrpLogInternal));
		(LdrpInitializeDllPath						= (tLdrpInitializeDllPath)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INITIALIZE_DLLPATH_PATTERN,			strlen(LDRP_INITIALIZE_DLLPATH_PATTERN))			,assert(LdrpInitializeDllPath));
		(LdrpDereferenceModule						= (tLdrpDereferenceModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DEREFERENCE_MODULE_PATTERN,			strlen(LDRP_DEREFERENCE_MODULE_PATTERN))			,assert(LdrpDereferenceModule));
		(LdrpLogDllState							= (tLdrpLogDllState)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DLLSTATE_PATTERN,					strlen(LDRP_LOG_DLLSTATE_PATTERN))					,assert(LdrpLogDllState));
		(LdrpPreprocessDllName						= (tLdrpPreprocessDllName)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PREPROCESS_DLLNAME_PATTERN,			strlen(LDRP_PREPROCESS_DLLNAME_PATTERN))			,assert(LdrpPreprocessDllName));
		(LdrpFastpthReloadedDll						= (tLdrpFastpthReloadedDll)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FASTPTH_RELOADED_DLL_PATTERN,			strlen(LDRP_FASTPTH_RELOADED_DLL_PATTERN))			,assert(LdrpFastpthReloadedDll));
		(LdrpDrainWorkQueue							= (tLdrpDrainWorkQueue)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DRAIN_WORKQUEUE_PATTERN,				strlen(LDRP_DRAIN_WORKQUEUE_PATTERN))				,assert(LdrpDrainWorkQueue));
		(LdrpFindLoadedDllByHandle					= (tLdrpFindLoadedDllByHandle)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN,		strlen(LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN))		,assert(LdrpFindLoadedDllByHandle));
		(LdrpDropLastInProgressCount				= (tLdrpDropLastInProgressCount)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN,	strlen(LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN))		,assert(LdrpDropLastInProgressCount));
		(LdrpQueryCurrentPatch						= (tLdrpQueryCurrentPatch)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_QUERY_CURRENT_PATCH_PATTERN,			strlen(LDRP_QUERY_CURRENT_PATCH_PATTERN))			,assert(LdrpQueryCurrentPatch));
		(LdrpUndoPatchImage							= (tLdrpUndoPatchImage)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_UNDO_PATCH_IMAGE_PATTERN,				strlen(LDRP_UNDO_PATCH_IMAGE_PATTERN))				,assert(LdrpUndoPatchImage));
		(LdrpDetectDetour							= (tLdrpDetectDetour)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DETECT_DETOUR_PATTERN,				strlen(LDRP_DETECT_DETOUR_PATTERN))					,assert(LdrpDetectDetour));
		(LdrpFindOrPrepareLoadingModule				= (tLdrpFindOrPrepareLoadingModule)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN,	strlen(LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN))	,assert(LdrpFindOrPrepareLoadingModule));
		(LdrpFreeLoadContext						= (tLdrpFreeLoadContext)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOAD_CONTEXT_PATTERN,			strlen(LDRP_FREE_LOAD_CONTEXT_PATTERN))				,assert(LdrpFreeLoadContext));
		(LdrpCondenseGraph							= (tLdrpCondenseGraph)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CONDENSE_GRAPH_PATTERN,				strlen(LDRP_CONDENSE_GRAPH_PATTERN))				,assert(LdrpCondenseGraph));
		(LdrpBuildForwarderLink						= (tLdrpBuildForwarderLink)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_BUILD_FORWARDER_LINK_PATTERN,			strlen(LDRP_BUILD_FORWARDER_LINK_PATTERN))			,assert(LdrpBuildForwarderLink));
		(LdrpPinModule								= (tLdrpPinModule)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PIN_MODULE_PATTERN,					strlen(LDRP_PIN_MODULE_PATTERN))					,assert(LdrpPinModule));
		(LdrpApplyPatchImage						= (tLdrpApplyPatchImage)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APPLY_PATCH_IMAGE_PATTERN,			strlen(LDRP_APPLY_PATCH_IMAGE_PATTERN))				,assert(LdrpApplyPatchImage));
		(LdrpFreeLoadContextOfNode					= (tLdrpFreeLoadContextOfNode)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOADCONTEXT_NODE_PATTERN,		strlen(LDRP_FREE_LOADCONTEXT_NODE_PATTERN))			,assert(LdrpFreeLoadContextOfNode));
		(LdrpDecrementModuleLoadCountEx				= (tLdrpDecrementModuleLoadCountEx)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN,	strlen(LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN))	,assert(LdrpDecrementModuleLoadCountEx));
		(LdrpLogError								= (tLdrpLogError)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_ERROR_PATTERN,					strlen(LDRP_LOG_ERROR_PATTERN))						,assert(LdrpLogError));
		(LdrpLogDeprecatedDllEtwEvent				= (tLdrpLogDeprecatedDllEtwEvent)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DEPRECATED_DLL_PATTERN,			strlen(LDRP_LOG_DEPRECATED_DLL_PATTERN))			,assert(LdrpLogDeprecatedDllEtwEvent));
		(LdrpLogLoadFailureEtwEvent					= (tLdrpLogLoadFailureEtwEvent)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_LOAD_FAILURE_PATTERN,				strlen(LDRP_LOG_LOAD_FAILURE_PATTERN))				,assert(LdrpLogLoadFailureEtwEvent));
		(LdrpReportError							= (tLdrpReportError)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_REPORT_ERROR_PATTERN,					strlen(LDRP_REPORT_ERROR_PATTERN))					,assert(LdrpReportError));
		(LdrpResolveDllName							= (tLdrpResolveDllName)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_RESOLVE_DLLNAME_PATTERN,				strlen(LDRP_RESOLVE_DLLNAME_PATTERN))				,assert(LdrpResolveDllName));
		(LdrpAppCompatRedirect						= (tLdrpAppCompatRedirect)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APP_COMPAT_REDIRECT_PATTERN,			strlen(LDRP_APP_COMPAT_REDIRECT_PATTERN))			,assert(LdrpAppCompatRedirect));
		(LdrpHashUnicodeString						= (tLdrpHashUnicodeString)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_HASH_UNICODE_STRING_PATTERN,			strlen(LDRP_HASH_UNICODE_STRING_PATTERN))			,assert(LdrpHashUnicodeString));
		(LdrpFindExistingModule						= (tLdrpFindExistingModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_EXISTING_MODULE_PATTERN,			strlen(LDRP_FIND_EXISTING_MODULE_PATTERN))			,assert(LdrpFindExistingModule));
		(LdrpLoadContextReplaceModule				= (tLdrpLoadContextReplaceModule)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOADCONTEXT_REPLACE_MODULE_PATTERN,	strlen(LDRP_LOADCONTEXT_REPLACE_MODULE_PATTERN))	,assert(LdrpLoadContextReplaceModule));
		(LdrpCheckForRetryLoading					= (tLdrpCheckForRetryLoading)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECKFORRETRY_LOADING_PATTERN,		strlen(LDRP_CHECKFORRETRY_LOADING_PATTERN))			,assert(LdrpCheckForRetryLoading));
		(LdrpLogEtwEvent							= (tLdrpLogEtwEvent)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_ETWEVENT_PATTERN,					strlen(LDRP_LOG_ETWEVENT_PATTERN))					,assert(LdrpLogEtwEvent));
		(LdrpCheckComponentOnDemandEtwEvent			= (tLdrpCheckComponentOnDemandEtwEvent)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECK_COMPONENTONDEMAND_PATTERN,		strlen(LDRP_CHECK_COMPONENTONDEMAND_PATTERN))		,assert(LdrpCheckComponentOnDemandEtwEvent));
		(LdrpValidateIntegrityContinuity			= (tLdrpValidateIntegrityContinuity)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_VALIDATE_INTEGRITY_PATTERN,			strlen(LDRP_VALIDATE_INTEGRITY_PATTERN))			,assert(LdrpValidateIntegrityContinuity));
		(LdrpSetModuleSigningLevel					= (tLdrpSetModuleSigningLevel)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_SET_MODULE_SIGNINGLEVEL_PATTERN,		strlen(LDRP_SET_MODULE_SIGNINGLEVEL_PATTERN))		,assert(LdrpSetModuleSigningLevel));
		(LdrpCodeAuthzCheckDllAllowed				= (tLdrpCodeAuthzCheckDllAllowed)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CODE_AUTHZCHECKDLL_ALLOWED_PATTERN,	strlen(LDRP_CODE_AUTHZCHECKDLL_ALLOWED_PATTERN))	,assert(LdrpCodeAuthzCheckDllAllowed));
		(LdrpGetFullPath							= (tLdrpGetFullPath)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_GET_FULLPATH_PATTERN,					strlen(LDRP_GET_FULLPATH_PATTERN))					,assert(LdrpGetFullPath));
		(LdrpAllocateUnicodeString					= (tLdrpAllocateUnicodeString)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_ALLOCATE_UNICODESTRING_PATTERN,		strlen(LDRP_ALLOCATE_UNICODESTRING_PATTERN))		,assert(LdrpAllocateUnicodeString));
		(LdrpAppendUnicodeStringToFilenameBuffer	= (tLdrpAppendUnicodeStringToFilenameBuffer)Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APPEND_UNICODETOFILENAME_PATTERN,		strlen(LDRP_APPEND_UNICODETOFILENAME_PATTERN))		,assert(LdrpAppendUnicodeStringToFilenameBuffer));
		(LdrpGetNtPathFromDosPath					= (tLdrpGetNtPathFromDosPath)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_GET_NTPATH_FROM_DOSPATH_PATTERN,		strlen(LDRP_GET_NTPATH_FROM_DOSPATH_PATTERN))		,assert(LdrpGetNtPathFromDosPath));
		(LdrpFindLoadedDllByNameLockHeld			= (tLdrpFindLoadedDllByNameLockHeld)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_LOCKHELD_PATTERN,		strlen(LDRP_FIND_LOADEDDLL_LOCKHELD_PATTERN))		,assert(LdrpFindLoadedDllByNameLockHeld));
		(LdrpFindLoadedDllByMappingLockHeld			= (tLdrpFindLoadedDllByMappingLockHeld)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_MAPLOCK_PATTERN,		strlen(LDRP_FIND_LOADEDDLL_MAPLOCK_PATTERN))		,assert(LdrpFindLoadedDllByMappingLockHeld));
		(LdrpInsertDataTableEntry					= (tLdrpInsertDataTableEntry)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INSERT_DATATABLEENTRY_PATTERN,		strlen(LDRP_INSERT_DATATABLEENTRY_PATTERN))			,assert(LdrpInsertDataTableEntry));
		(LdrpInsertModuleToIndexLockHeld			= (tLdrpInsertModuleToIndexLockHeld)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INSERT_MODTOIDX_LOCKHELD_PATTERN,		strlen(LDRP_INSERT_MODTOIDX_LOCKHELD_PATTERN))		,assert(LdrpInsertModuleToIndexLockHeld));
		(LdrpLogEtwHotPatchStatus					= (tLdrpLogEtwHotPatchStatus)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOGETW_HOTPATCHSTATUS_PATTERN,		strlen(LDRP_LOGETW_HOTPATCHSTATUS_PATTERN))			,assert(LdrpLogEtwHotPatchStatus));
		(LdrpLogNewDllLoad							= (tLdrpLogNewDllLoad)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_NEWDLL_LOAD_PATTERN,				strlen(LDRP_LOG_NEWDLL_LOAD_PATTERN))				,assert(LdrpLogNewDllLoad));
		(LdrpProcessMachineMismatch					= (tLdrpProcessMachineMismatch)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PROCESS_MACHINE_MISMATCH_PATTERN,		strlen(LDRP_PROCESS_MACHINE_MISMATCH_PATTERN))		,assert(LdrpProcessMachineMismatch));
		(RtlQueryImageFileKeyOption					= (tRtlQueryImageFileKeyOption)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTL_QUERY_IMAGEFILE_KEYOPT_PATTERN,		strlen(RTL_QUERY_IMAGEFILE_KEYOPT_PATTERN))			,assert(RtlQueryImageFileKeyOption));
		(RtlpImageDirectoryEntryToDataEx			= (tRtlpImageDirectoryEntryToDataEx)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTLP_IMAGEDIR_ENTRYTODATA_PATTERN,			strlen(RTLP_IMAGEDIR_ENTRYTODATA_PATTERN))			,assert(RtlpImageDirectoryEntryToDataEx));

		WID_DBG( printf("[WID] >> Initialized.\n"); )

		bInitialized = TRUE;
		return STATUS_SUCCESS;
	}
	WID_DBG( printf("[WID] >> Already initialized.\n"); )
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