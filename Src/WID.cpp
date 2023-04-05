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
		HMODULE Kernel32Module		= GetModuleHandle(TEXT("KERNEL32.DLL"));
		assert(Kernel32Module);

		HMODULE KernelBaseModule	= GetModuleHandle(TEXT("KERNELBASE.DLL"));
		assert(KernelBaseModule);

		HMODULE NtdllModule			= GetModuleHandle(TEXT("NTDLL.DLL"));
		assert(NtdllModule);

		(GetModuleInformation(GetCurrentProcess(), Kernel32Module,		&Kernel32ModuleInfo,	sizeof(MODULEINFO)),	assert(Kernel32ModuleInfo.lpBaseOfDll));
		(GetModuleInformation(GetCurrentProcess(), KernelBaseModule,	&KernelBaseModuleInfo,	sizeof(MODULEINFO)),	assert(KernelBaseModuleInfo.lpBaseOfDll));
		(GetModuleInformation(GetCurrentProcess(), NtdllModule,			&NtdllModuleInfo,		sizeof(MODULEINFO)),	assert(NtdllModuleInfo.lpBaseOfDll));

		// KERNEL32
		// Variables
		(KernelBaseGlobalData					= (ULONG*)								((PCHAR)Kernel32Module + 0x34DE80)							,assert(KernelBaseGlobalData));

		// Exported functions
		(Basep8BitStringToDynamicUnicodeString	= (tBasep8BitStringToDynamicUnicodeString)GetProcAddress(Kernel32Module, "Basep8BitStringToDynamicUnicodeString")	,assert(Basep8BitStringToDynamicUnicodeString));
		(BaseSetLastNTError						= (tBaseSetLastNTError)GetProcAddress(Kernel32Module, "BaseSetLastNTError")											,assert(BaseSetLastNTError));

		// KERNELBASE
		// Signatured
		(BasepLoadLibraryAsDataFileInternal		= (tBasepLoadLibraryAsDataFileInternal)	Helper::SigScan((PCHAR)KernelBaseModule, KernelBaseModuleInfo.SizeOfImage, BASEP_LLASDATAFILE_INTERNAL_PATTERN, ARRAYSIZE(BASEP_LLASDATAFILE_INTERNAL_PATTERN) - 1), assert(BasepLoadLibraryAsDataFileInternal));

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
		(LdrpHashTable							= (LIST_ENTRY*)							((PCHAR)NtdllModule + 0x183FE0)								,assert(LdrpHashTable));
		(LdrpHeap								= (PVOID*)								((PCHAR)NtdllModule + 0x1843E0)								,assert(LdrpHeap));
		(LdrpIsHotPatchingEnabled				= (BOOLEAN*)							((PCHAR)NtdllModule + 0x185258)								,assert(LdrpIsHotPatchingEnabled));
		(LdrpRedirectionModule					= (LDR_DATA_TABLE_ENTRY**)				((PCHAR)NtdllModule + 0x184218)								,assert(LdrpRedirectionModule));
		(LdrpManifestProberRoutine				= (tLdrpManifestProberRoutine)			((PCHAR)NtdllModule + 0x184C20)								,assert(LdrpManifestProberRoutine));
		(LdrpRedirectionCalloutFunc				= (tLdrpRedirectionCalloutFunc)			((PCHAR)NtdllModule + 0x184228)								,assert(LdrpRedirectionCalloutFunc));
		(qword_1993A8							= (ULONG64**)							((PCHAR)NtdllModule + 0x1993A8)								,assert(qword_1993A8));
		(NtdllBaseTag							= (LONG*)								((PCHAR)NtdllModule + 0x1843F0)								,assert(NtdllBaseTag));
		(stru_199520							= (FUNCTION_TABLE_DATA*)				((PCHAR)NtdllModule + 0x199520)								,assert(stru_199520));
		(qword_199530							= (UINT_PTR*)							((PCHAR)NtdllModule + 0x199530)								,assert(qword_199530));
		(LdrpNtDllDataTableEntry				= (LDR_DATA_TABLE_ENTRY**)				((PCHAR)NtdllModule + 0x184370)								,assert(LdrpNtDllDataTableEntry));
		(qword_1993B8							= (UINT_PTR*)							((PCHAR)NtdllModule + 0x1993B8)								,assert(qword_1993B8));
		(dword_19939C							= (DWORD*)								((PCHAR)NtdllModule + 0x19939C)								,assert(dword_19939C));
		(LoadFailureOperational					= (DWORD*)								((PCHAR)NtdllModule + 0x14BA98)								,assert(LoadFailureOperational));
		(dword_199398							= (DWORD*)								((PCHAR)NtdllModule + 0x199398)								,assert(dword_199398));
		(qword_1843B8							= (UINT_PTR***)							((PCHAR)NtdllModule + 0x1843B8)								,assert(qword_1843B8));
		(qword_1843B0							= (UINT_PTR*)							((PCHAR)NtdllModule + 0x1843B0)								,assert(qword_1843B0));
		(LdrpCurrentDllInitializer				= (UINT_PTR*)							((PCHAR)NtdllModule + 0x184A88)								,assert(LdrpCurrentDllInitializer));
		(LdrpProcessInitContextRecord			= (LPVOID**)							((PCHAR)NtdllModule + 0x184358)								,assert(LdrpProcessInitContextRecord));
		(LdrpTlsLock							= (PRTL_SRWLOCK)						((PCHAR)NtdllModule + 0x184EF8)								,assert(LdrpTlsLock));
		(LdrpTlsList							= (TLS_ENTRY**)							((PCHAR)NtdllModule + 0x17E2B0)								,assert(LdrpTlsList));

		// Exported functions
		(NtOpenThreadToken						= (tNtOpenThreadToken)							GetProcAddress(NtdllModule, "NtOpenThreadToken")						,assert(NtOpenThreadToken));
		(NtClose								= (tNtClose)									GetProcAddress(NtdllModule, "NtClose")									,assert(NtClose));
		(RtlAllocateHeap						= (tRtlAllocateHeap)							GetProcAddress(NtdllModule, "RtlAllocateHeap")							,assert(RtlAllocateHeap));
		(RtlFreeHeap							= (tRtlFreeHeap)								GetProcAddress(NtdllModule, "RtlFreeHeap")								,assert(RtlFreeHeap));
		(LdrGetDllPath							= (tLdrGetDllPath)								GetProcAddress(NtdllModule, "LdrGetDllPath")							,assert(LdrGetDllPath));
		(RtlReleasePath							= (tRtlReleasePath)								GetProcAddress(NtdllModule, "RtlReleasePath")							,assert(RtlReleasePath));
		(RtlInitUnicodeStringEx					= (tRtlInitUnicodeStringEx)						GetProcAddress(NtdllModule, "RtlInitUnicodeStringEx")					,assert(RtlInitUnicodeStringEx));
		(RtlEnterCriticalSection				= (tRtlEnterCriticalSection)					GetProcAddress(NtdllModule, "RtlEnterCriticalSection")					,assert(RtlEnterCriticalSection));
		(RtlLeaveCriticalSection				= (tRtlLeaveCriticalSection)					GetProcAddress(NtdllModule, "RtlLeaveCriticalSection")					,assert(RtlLeaveCriticalSection));
		(ZwSetEvent								= (tZwSetEvent)									GetProcAddress(NtdllModule, "ZwSetEvent")								,assert(ZwSetEvent));
		(NtOpenFile								= (tNtOpenFile)									GetProcAddress(NtdllModule, "NtOpenFile")								,assert(NtOpenFile));
		(LdrAppxHandleIntegrityFailure			= (tLdrAppxHandleIntegrityFailure)				GetProcAddress(NtdllModule, "LdrAppxHandleIntegrityFailure")			,assert(LdrAppxHandleIntegrityFailure));
		(NtRaiseHardError						= (tNtRaiseHardError)							GetProcAddress(NtdllModule, "NtRaiseHardError")							,assert(NtRaiseHardError));
		(RtlImageNtHeaderEx						= (tRtlImageNtHeaderEx)							GetProcAddress(NtdllModule, "RtlImageNtHeaderEx")						,assert(RtlImageNtHeaderEx));
		(RtlAcquireSRWLockExclusive				= (tRtlAcquireSRWLockExclusive)					GetProcAddress(NtdllModule, "RtlAcquireSRWLockExclusive")				,assert(RtlAcquireSRWLockExclusive));
		(RtlReleaseSRWLockExclusive				= (tRtlReleaseSRWLockExclusive)					GetProcAddress(NtdllModule, "RtlReleaseSRWLockExclusive")				,assert(RtlReleaseSRWLockExclusive));
		(RtlEqualUnicodeString					= (tRtlEqualUnicodeString)						GetProcAddress(NtdllModule, "RtlEqualUnicodeString")					,assert(RtlEqualUnicodeString));
		(RtlAcquirePrivilege					= (tRtlAcquirePrivilege)						GetProcAddress(NtdllModule, "RtlAcquirePrivilege")						,assert(RtlAcquirePrivilege));
		(RtlReleasePrivilege					= (tRtlReleasePrivilege)						GetProcAddress(NtdllModule, "RtlReleasePrivilege")						,assert(RtlReleasePrivilege));
		(RtlCompareUnicodeStrings				= (tRtlCompareUnicodeStrings)					GetProcAddress(NtdllModule, "RtlCompareUnicodeStrings")					,assert(RtlCompareUnicodeStrings));
		(RtlImageNtHeader						= (tRtlImageNtHeader)							GetProcAddress(NtdllModule, "RtlImageNtHeader")							,assert(RtlImageNtHeader));
		(RtlReleaseActivationContext			= (tRtlReleaseActivationContext)				GetProcAddress(NtdllModule, "RtlReleaseActivationContext")				,assert(RtlReleaseActivationContext));
		(RtlCharToInteger						= (tRtlCharToInteger)							GetProcAddress(NtdllModule, "RtlCharToInteger")							,assert(RtlCharToInteger));
		(RtlActivateActivationContextUnsafeFast = (tRtlActivateActivationContextUnsafeFast)		GetProcAddress(NtdllModule, "RtlActivateActivationContextUnsafeFast")	,assert(RtlActivateActivationContextUnsafeFast));
		(RtlDeactivateActivationContextUnsafeFast = (tRtlDeactivateActivationContextUnsafeFast)	GetProcAddress(NtdllModule, "RtlDeactivateActivationContextUnsafeFast")	,assert(RtlDeactivateActivationContextUnsafeFast));
		(RtlAcquireSRWLockShared				= (tRtlAcquireSRWLockShared)					GetProcAddress(NtdllModule, "RtlAcquireSRWLockShared")					,assert(RtlAcquireSRWLockShared));
		(RtlReleaseSRWLockShared				= (tRtlReleaseSRWLockShared)					GetProcAddress(NtdllModule, "RtlReleaseSRWLockShared")					,assert(RtlReleaseSRWLockShared));

		// Signatured.
		// I don't think the signatures will ever change, you can go with the offsets though.
		(LdrpLogInternal							= (tLdrpLogInternal)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_INTERNAL_PATTERN,							ARRAYSIZE(LDRP_LOG_INTERNAL_PATTERN)				- 1)	,assert(LdrpLogInternal));
		(LdrpInitializeDllPath						= (tLdrpInitializeDllPath)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INITIALIZE_DLLPATH_PATTERN,					ARRAYSIZE(LDRP_INITIALIZE_DLLPATH_PATTERN)			- 1)	,assert(LdrpInitializeDllPath));
		(LdrpDereferenceModule						= (tLdrpDereferenceModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DEREFERENCE_MODULE_PATTERN,					ARRAYSIZE(LDRP_DEREFERENCE_MODULE_PATTERN)			- 1)	,assert(LdrpDereferenceModule));
		(LdrpLogDllState							= (tLdrpLogDllState)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DLLSTATE_PATTERN,							ARRAYSIZE(LDRP_LOG_DLLSTATE_PATTERN)				- 1)	,assert(LdrpLogDllState));
		(LdrpPreprocessDllName						= (tLdrpPreprocessDllName)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PREPROCESS_DLLNAME_PATTERN,					ARRAYSIZE(LDRP_PREPROCESS_DLLNAME_PATTERN)			- 1)	,assert(LdrpPreprocessDllName));
		(LdrpFindLoadedDllByName					= (tLdrpFindLoadedDllByName)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLLBYNAME_PATTERN,					ARRAYSIZE(LDRP_FIND_LOADEDDLLBYNAME_PATTERN)		- 1)	,assert(LdrpFindLoadedDllByName));
		(LdrpDrainWorkQueue							= (tLdrpDrainWorkQueue)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DRAIN_WORKQUEUE_PATTERN,						ARRAYSIZE(LDRP_DRAIN_WORKQUEUE_PATTERN)				- 1)	,assert(LdrpDrainWorkQueue));
		(LdrpFindLoadedDllByHandle					= (tLdrpFindLoadedDllByHandle)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN,				ARRAYSIZE(LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN)		- 1)	,assert(LdrpFindLoadedDllByHandle));
		(LdrpDropLastInProgressCount				= (tLdrpDropLastInProgressCount)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN,			ARRAYSIZE(LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN)	- 1)	,assert(LdrpDropLastInProgressCount));
		(LdrpQueryCurrentPatch						= (tLdrpQueryCurrentPatch)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_QUERY_CURRENT_PATCH_PATTERN,					ARRAYSIZE(LDRP_QUERY_CURRENT_PATCH_PATTERN)			- 1)	,assert(LdrpQueryCurrentPatch));
		(LdrpUndoPatchImage							= (tLdrpUndoPatchImage)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_UNDO_PATCH_IMAGE_PATTERN,						ARRAYSIZE(LDRP_UNDO_PATCH_IMAGE_PATTERN)			- 1)	,assert(LdrpUndoPatchImage));
		(LdrpDetectDetour							= (tLdrpDetectDetour)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DETECT_DETOUR_PATTERN,						ARRAYSIZE(LDRP_DETECT_DETOUR_PATTERN)				- 1)	,assert(LdrpDetectDetour));
		(LdrpFindOrPrepareLoadingModule				= (tLdrpFindOrPrepareLoadingModule)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN,			ARRAYSIZE(LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN) - 1)	,assert(LdrpFindOrPrepareLoadingModule));
		(LdrpFreeLoadContext						= (tLdrpFreeLoadContext)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOAD_CONTEXT_PATTERN,					ARRAYSIZE(LDRP_FREE_LOAD_CONTEXT_PATTERN)			- 1)	,assert(LdrpFreeLoadContext));
		(LdrpCondenseGraph							= (tLdrpCondenseGraph)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CONDENSE_GRAPH_PATTERN,						ARRAYSIZE(LDRP_CONDENSE_GRAPH_PATTERN)				- 1)	,assert(LdrpCondenseGraph));
		(LdrpBuildForwarderLink						= (tLdrpBuildForwarderLink)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_BUILD_FORWARDER_LINK_PATTERN,					ARRAYSIZE(LDRP_BUILD_FORWARDER_LINK_PATTERN)		- 1)	,assert(LdrpBuildForwarderLink));
		(LdrpPinModule								= (tLdrpPinModule)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PIN_MODULE_PATTERN,							ARRAYSIZE(LDRP_PIN_MODULE_PATTERN)					- 1)	,assert(LdrpPinModule));
		(LdrpApplyPatchImage						= (tLdrpApplyPatchImage)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APPLY_PATCH_IMAGE_PATTERN,					ARRAYSIZE(LDRP_APPLY_PATCH_IMAGE_PATTERN)			- 1)	,assert(LdrpApplyPatchImage));
		(LdrpFreeLoadContextOfNode					= (tLdrpFreeLoadContextOfNode)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FREE_LOADCONTEXT_NODE_PATTERN,				ARRAYSIZE(LDRP_FREE_LOADCONTEXT_NODE_PATTERN)		- 1)	,assert(LdrpFreeLoadContextOfNode));
		(LdrpDecrementModuleLoadCountEx				= (tLdrpDecrementModuleLoadCountEx)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN,			ARRAYSIZE(LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN) - 1)	,assert(LdrpDecrementModuleLoadCountEx));
		(LdrpLogError								= (tLdrpLogError)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_ERROR_PATTERN,							ARRAYSIZE(LDRP_LOG_ERROR_PATTERN)					- 1)	,assert(LdrpLogError));
		(LdrpLogDeprecatedDllEtwEvent				= (tLdrpLogDeprecatedDllEtwEvent)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DEPRECATED_DLL_PATTERN,					ARRAYSIZE(LDRP_LOG_DEPRECATED_DLL_PATTERN)			- 1)	,assert(LdrpLogDeprecatedDllEtwEvent));
		(LdrpLogLoadFailureEtwEvent					= (tLdrpLogLoadFailureEtwEvent)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_LOAD_FAILURE_PATTERN,						ARRAYSIZE(LDRP_LOG_LOAD_FAILURE_PATTERN)			- 1)	,assert(LdrpLogLoadFailureEtwEvent));
		(LdrpReportError							= (tLdrpReportError)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_REPORT_ERROR_PATTERN,							ARRAYSIZE(LDRP_REPORT_ERROR_PATTERN)				- 1)	,assert(LdrpReportError));
		(LdrpResolveDllName							= (tLdrpResolveDllName)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_RESOLVE_DLLNAME_PATTERN,						ARRAYSIZE(LDRP_RESOLVE_DLLNAME_PATTERN)				- 1)	,assert(LdrpResolveDllName));
		(LdrpAppCompatRedirect						= (tLdrpAppCompatRedirect)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APP_COMPAT_REDIRECT_PATTERN,					ARRAYSIZE(LDRP_APP_COMPAT_REDIRECT_PATTERN)			- 1)	,assert(LdrpAppCompatRedirect));
		(LdrpHashUnicodeString						= (tLdrpHashUnicodeString)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_HASH_UNICODE_STRING_PATTERN,					ARRAYSIZE(LDRP_HASH_UNICODE_STRING_PATTERN)			- 1)	,assert(LdrpHashUnicodeString));
		(LdrpFindExistingModule						= (tLdrpFindExistingModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_EXISTING_MODULE_PATTERN,					ARRAYSIZE(LDRP_FIND_EXISTING_MODULE_PATTERN)		- 1)	,assert(LdrpFindExistingModule));
		(LdrpLoadContextReplaceModule				= (tLdrpLoadContextReplaceModule)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOADCONTEXT_REPLACE_MODULE_PATTERN,			ARRAYSIZE(LDRP_LOADCONTEXT_REPLACE_MODULE_PATTERN)	- 1)	,assert(LdrpLoadContextReplaceModule));
		(LdrpSearchPath								= (tLdrpSearchPath)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_SEARCHPATH_PATTERN,							ARRAYSIZE(LDRP_SEARCHPATH_PATTERN)					- 1)	,assert(LdrpSearchPath));
		(LdrpIsSecurityEtwLoggingEnabled			= (tLdrpIsSecurityEtwLoggingEnabled)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_ISSECURITYETW_LOGG_ENABLED_PATTERN,			ARRAYSIZE(LDRP_ISSECURITYETW_LOGG_ENABLED_PATTERN)	- 1)	,assert(LdrpIsSecurityEtwLoggingEnabled));
		(LdrpLogEtwDllSearchResults					= (tLdrpLogEtwDllSearchResults)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOGETW_DLL_SEARCHRESULTS_PATTERN,				ARRAYSIZE(LDRP_LOGETW_DLL_SEARCHRESULTS_PATTERN)	- 1)	,assert(LdrpLogEtwDllSearchResults));
		(LdrpCheckForRetryLoading					= (tLdrpCheckForRetryLoading)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECKFORRETRY_LOADING_PATTERN,				ARRAYSIZE(LDRP_CHECKFORRETRY_LOADING_PATTERN)		- 1)	,assert(LdrpCheckForRetryLoading));
		(LdrpLogEtwEvent							= (tLdrpLogEtwEvent)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_ETWEVENT_PATTERN,							ARRAYSIZE(LDRP_LOG_ETWEVENT_PATTERN)				- 1)	,assert(LdrpLogEtwEvent));
		(LdrpCheckComponentOnDemandEtwEvent			= (tLdrpCheckComponentOnDemandEtwEvent)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECK_COMPONENTONDEMAND_PATTERN,				ARRAYSIZE(LDRP_CHECK_COMPONENTONDEMAND_PATTERN)		- 1)	,assert(LdrpCheckComponentOnDemandEtwEvent));
		(LdrpValidateIntegrityContinuity			= (tLdrpValidateIntegrityContinuity)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_VALIDATE_INTEGRITY_PATTERN,					ARRAYSIZE(LDRP_VALIDATE_INTEGRITY_PATTERN)			- 1)	,assert(LdrpValidateIntegrityContinuity));
		(LdrpSetModuleSigningLevel					= (tLdrpSetModuleSigningLevel)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_SET_MODULE_SIGNINGLEVEL_PATTERN,				ARRAYSIZE(LDRP_SET_MODULE_SIGNINGLEVEL_PATTERN)		- 1)	,assert(LdrpSetModuleSigningLevel));
		(LdrpCodeAuthzCheckDllAllowed				= (tLdrpCodeAuthzCheckDllAllowed)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CODE_AUTHZCHECKDLL_ALLOWED_PATTERN,			ARRAYSIZE(LDRP_CODE_AUTHZCHECKDLL_ALLOWED_PATTERN)	- 1)	,assert(LdrpCodeAuthzCheckDllAllowed));
		(LdrpGetFullPath							= (tLdrpGetFullPath)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_GET_FULLPATH_PATTERN,							ARRAYSIZE(LDRP_GET_FULLPATH_PATTERN)				- 1)	,assert(LdrpGetFullPath));
		(LdrpAllocateUnicodeString					= (tLdrpAllocateUnicodeString)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_ALLOCATE_UNICODESTRING_PATTERN,				ARRAYSIZE(LDRP_ALLOCATE_UNICODESTRING_PATTERN)		- 1)	,assert(LdrpAllocateUnicodeString));
		(LdrpAppendUnicodeStringToFilenameBuffer	= (tLdrpAppendUnicodeStringToFilenameBuffer)Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_APPEND_UNICODETOFILENAME_PATTERN,				ARRAYSIZE(LDRP_APPEND_UNICODETOFILENAME_PATTERN)	- 1)	,assert(LdrpAppendUnicodeStringToFilenameBuffer));
		(LdrpGetNtPathFromDosPath					= (tLdrpGetNtPathFromDosPath)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_GET_NTPATH_FROM_DOSPATH_PATTERN,				ARRAYSIZE(LDRP_GET_NTPATH_FROM_DOSPATH_PATTERN)		- 1)	,assert(LdrpGetNtPathFromDosPath));
		(LdrpFindLoadedDllByMappingLockHeld			= (tLdrpFindLoadedDllByMappingLockHeld)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_FIND_LOADEDDLL_MAPLOCK_PATTERN,				ARRAYSIZE(LDRP_FIND_LOADEDDLL_MAPLOCK_PATTERN)		- 1)	,assert(LdrpFindLoadedDllByMappingLockHeld));
		(LdrpInsertDataTableEntry					= (tLdrpInsertDataTableEntry)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INSERT_DATATABLEENTRY_PATTERN,				ARRAYSIZE(LDRP_INSERT_DATATABLEENTRY_PATTERN)		- 1)	,assert(LdrpInsertDataTableEntry));
		(LdrpInsertModuleToIndexLockHeld			= (tLdrpInsertModuleToIndexLockHeld)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_INSERT_MODTOIDX_LOCKHELD_PATTERN,				ARRAYSIZE(LDRP_INSERT_MODTOIDX_LOCKHELD_PATTERN)	- 1)	,assert(LdrpInsertModuleToIndexLockHeld));
		(LdrpLogEtwHotPatchStatus					= (tLdrpLogEtwHotPatchStatus)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOGETW_HOTPATCHSTATUS_PATTERN,				ARRAYSIZE(LDRP_LOGETW_HOTPATCHSTATUS_PATTERN)		- 1)	,assert(LdrpLogEtwHotPatchStatus));
		(LdrpLogNewDllLoad							= (tLdrpLogNewDllLoad)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_NEWDLL_LOAD_PATTERN,						ARRAYSIZE(LDRP_LOG_NEWDLL_LOAD_PATTERN)				- 1)	,assert(LdrpLogNewDllLoad));
		(LdrpProcessMachineMismatch					= (tLdrpProcessMachineMismatch)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_PROCESS_MACHINE_MISMATCH_PATTERN,				ARRAYSIZE(LDRP_PROCESS_MACHINE_MISMATCH_PATTERN)	- 1)	,assert(LdrpProcessMachineMismatch));
		(RtlQueryImageFileKeyOption					= (tRtlQueryImageFileKeyOption)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTL_QUERY_IMAGEFILE_KEYOPT_PATTERN,				ARRAYSIZE(RTL_QUERY_IMAGEFILE_KEYOPT_PATTERN)		- 1)	,assert(RtlQueryImageFileKeyOption));
		(RtlpImageDirectoryEntryToDataEx			= (tRtlpImageDirectoryEntryToDataEx)		Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTLP_IMAGEDIR_ENTRYTODATA_PATTERN,					ARRAYSIZE(RTLP_IMAGEDIR_ENTRYTODATA_PATTERN)		- 1)	,assert(RtlpImageDirectoryEntryToDataEx));
		(LdrpLogDllRelocationEtwEvent				= (tLdrpLogDllRelocationEtwEvent)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOG_DLLRELOCATION_PATTERN,					ARRAYSIZE(LDRP_LOG_DLLRELOCATION_PATTERN)			- 1)	,assert(LdrpLogDllRelocationEtwEvent));
		(LdrpNotifyLoadOfGraph						= (tLdrpNotifyLoadOfGraph)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_NOTIFY_LOADOFGRAPH_PATTERN,					ARRAYSIZE(LDRP_NOTIFY_LOADOFGRAPH_PATTERN)			- 1)	,assert(LdrpNotifyLoadOfGraph));
		(LdrpDynamicShimModule						= (tLdrpDynamicShimModule)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_DYNAMIC_SHIMMODULE_PATTERN,					ARRAYSIZE(LDRP_DYNAMIC_SHIMMODULE_PATTERN)			- 1)	,assert(LdrpDynamicShimModule));
		(LdrpAcquireLoaderLock						= (tLdrpAcquireLoaderLock)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_ACQUIRE_LOADERLOCK_PATTERN,					ARRAYSIZE(LDRP_ACQUIRE_LOADERLOCK_PATTERN)			- 1)	,assert(LdrpAcquireLoaderLock));
		(LdrpReleaseLoaderLock						= (tLdrpReleaseLoaderLock)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_RELEASE_LOADER_LOCK_PATTERN,					ARRAYSIZE(LDRP_RELEASE_LOADER_LOCK_PATTERN)			- 1)	,assert(LdrpReleaseLoaderLock));
		(LdrpCheckPagesForTampering					= (tLdrpCheckPagesForTampering)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECKPAGES_FOR_TAMPERING_PATTERN,				ARRAYSIZE(LDRP_CHECKPAGES_FOR_TAMPERING_PATTERN)	- 1)	,assert(LdrpCheckPagesForTampering));
		(LdrpLoadDependentModuleA					= (tLdrpLoadDependentModuleA)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOAD_DEPENDENTMODULEA_PATTERN,				ARRAYSIZE(LDRP_LOAD_DEPENDENTMODULEA_PATTERN)		- 1)	,assert(LdrpLoadDependentModuleA));
		(LdrpLoadDependentModuleW					= (tLdrpLoadDependentModuleW)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_LOAD_DEPENDENTMODULEW_PATTERN,				ARRAYSIZE(LDRP_LOAD_DEPENDENTMODULEW_PATTERN)		- 1)	,assert(LdrpLoadDependentModuleW));
		(LdrpQueueWork								= (tLdrpQueueWork)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_QUEUE_WORK_PATTERN,							ARRAYSIZE(LDRP_QUEUE_WORK_PATTERN)					- 1)	,assert(LdrpQueueWork));
		(LdrpHandleTlsData							= (tLdrpHandleTlsData)						Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_HANDLE_TLSDATA_PATTERN,						ARRAYSIZE(LDRP_HANDLE_TLSDATA_PATTERN)				- 1)	,assert(LdrpHandleTlsData));
		(LdrControlFlowGuardEnforcedWithExportSuppression = (tLdrControlFlowGuardEnforcedWithExportSuppression)Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDR_CONTROLFLOWGUARD_ENFEXP_PATTERN,ARRAYSIZE(LDR_CONTROLFLOWGUARD_ENFEXP_PATTERN)		- 1)	,assert(LdrControlFlowGuardEnforcedWithExportSuppression));
		(LdrpUnsuppressAddressTakenIat				= (tLdrpUnsuppressAddressTakenIat)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_UNSUPPRESS_ADDRESSIAT_PATTERN,				ARRAYSIZE(LDRP_UNSUPPRESS_ADDRESSIAT_PATTERN)		- 1)	,assert(LdrpUnsuppressAddressTakenIat));
		(LdrControlFlowGuardEnforced				= (tLdrControlFlowGuardEnforced)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDR_CONTROLFLOWGUARD_ENF_PATTERN,					ARRAYSIZE(LDR_CONTROLFLOWGUARD_ENF_PATTERN)			- 1)	,assert(LdrControlFlowGuardEnforced));
		(RtlpxLookupFunctionTable					= (tRtlpxLookupFunctionTable)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTLP_LOOKUP_FUNCTIONTABLE_PATTERN,					ARRAYSIZE(RTLP_LOOKUP_FUNCTIONTABLE_PATTERN)		- 1)	,assert(RtlpxLookupFunctionTable));
		(LdrpCheckRedirection						= (tLdrpCheckRedirection)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CHECK_REDIRECTION_PATTERN,					ARRAYSIZE(LDRP_CHECK_REDIRECTION_PATTERN)			- 1)	,assert(LdrpCheckRedirection));
		(CompatCachepLookupCdb						= (tCompatCachepLookupCdb)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, COMPAT_CACHE_LOOKUPCDB_PATTERN,					ARRAYSIZE(COMPAT_CACHE_LOOKUPCDB_PATTERN)			- 1)	,assert(CompatCachepLookupCdb));
		(LdrpGenRandom								= (tLdrpGenRandom)							Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_GEN_RANDOM_PATTERN,							ARRAYSIZE(LDRP_GEN_RANDOM_PATTERN)					- 1)	,assert(LdrpGenRandom));
		(LdrInitSecurityCookie						= (tLdrInitSecurityCookie)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDR_INIT_SECURITY_COOKIE_PATTERN,					ARRAYSIZE(LDR_INIT_SECURITY_COOKIE_PATTERN)			- 1)	,assert(LdrInitSecurityCookie));
		(LdrpCfgProcessLoadConfig					= (tLdrpCfgProcessLoadConfig)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CFG_PROCESS_LOADCFG_PATTERN,					ARRAYSIZE(LDRP_CFG_PROCESS_LOADCFG_PATTERN)			- 1)	,assert(LdrpCfgProcessLoadConfig));
		(RtlInsertInvertedFunctionTable				= (tRtlInsertInvertedFunctionTable)			Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, RTL_INSERT_INV_FUNCTIONTABLE_PATTERN,				ARRAYSIZE(RTL_INSERT_INV_FUNCTIONTABLE_PATTERN)		- 1)	,assert(RtlInsertInvertedFunctionTable));
		(LdrpSignalModuleMapped						= (tLdrpSignalModuleMapped)					Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_SIGNAL_MODULEMAPPED_PATTERN,					ARRAYSIZE(LDRP_SIGNAL_MODULEMAPPED_PATTERN)			- 1)	,assert(LdrpSignalModuleMapped));
		(AVrfDllLoadNotification					= (tAVrfDllLoadNotification)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, AVRF_DLL_LOADNOTIFICATION_PATTERN,					ARRAYSIZE(AVRF_DLL_LOADNOTIFICATION_PATTERN)		- 1)	,assert(AVrfDllLoadNotification));
		(LdrpSendDllNotifications					= (tLdrpSendDllNotifications)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_SEND_DLLNOTIFICATIONS_PATTERN,				ARRAYSIZE(LDRP_SEND_DLLNOTIFICATIONS_PATTERN)		- 1)	,assert(LdrpSendDllNotifications));
		(LdrpCallTlsInitializers					= (tLdrpCallTlsInitializers)				Helper::SigScan((PCHAR)NtdllModule, NtdllModuleInfo.SizeOfImage, LDRP_CALL_TLSINIT_PATTERN,							ARRAYSIZE(LDRP_CALL_TLSINIT_PATTERN)				- 1)	,assert(LdrpCallTlsInitializers));

		WID_DBG(TEXT("[WID] >> Initialized.\n"));

		bInitialized = TRUE;
		return STATUS_SUCCESS;
	}

	WID_DBG(TEXT("[WID] >> Already initialized.\n"));
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
			if (Pattern[i2] != 0x90 && StartAddress[i1 + i2] != Pattern[i2])
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