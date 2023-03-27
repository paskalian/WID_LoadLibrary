#pragma once

#include "..\Includes.h"
#include "..\WID.h"
#include "Undocumented.h"


#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS						0x0
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH	0x4000000E
#define STATUS_DEVICE_OFF_LINE				0x80000010
#define STATUS_UNSUCCESSFUL					0xC0000001
#define STATUS_ACCESS_DENIED				0xC0000022
#define STATUS_OBJECT_NAME_NOT_FOUND		0xC0000034
#define STATUS_OBJECT_PATH_NOT_FOUND		0xC000003A
#define STATUS_NO_SUCH_FILE					0xC000000F
#define STATUS_DEVICE_NOT_READY				0xC00000A3
#define STATUS_INVALID_IMAGE_FORMAT			0xC000007B
#define STATUS_NO_TOKEN						0xC000007C
#define STATUS_INSUFFICIENT_RESOURCES		0xC000009A
#define STATUS_COMMITMENT_LIMIT				0xC000012D
#define STATUS_NO_APPLICATION_PACKAGE		0xC00001AA
#define STATUS_NOT_FOUND					0xC0000225
#define STATUS_RETRY						0xC000022D
#define STATUS_NEEDS_REMEDIATION			0xC0000462
#define STATUS_PATCH_CONFLICT				0xC00004AC
#define STATUS_IMAGE_LOADED_AS_PATCH_IMAGE	0xC00004C0
#define STATUS_INVALID_THREAD				0xC000071C

// Implemented.
extern HANDLE*					LdrpMainThreadToken;
extern DWORD*					LdrInitState;
extern DWORD*					LoadFailure;
extern PRTL_CRITICAL_SECTION	LdrpWorkQueueLock;
extern DWORD*					LdrpWorkInProgress;
extern LIST_ENTRY**				LdrpWorkQueue;
extern PHANDLE					LdrpWorkCompleteEvent;
extern KUSER_SHARED_DATA*		kUserSharedData;
extern DWORD*					LdrpUseImpersonatedDeviceMap;
extern DWORD*					LdrpAuditIntegrityContinuity;
extern DWORD*					LdrpEnforceIntegrityContinuity;
extern DWORD*					LdrpFatalHardErrorCount;
extern DWORD*					UseWOW64;

PEB* NtCurrentPeb();
VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer);
VOID __fastcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
VOID __fastcall LdrpFreeUnicodeString(PUNICODE_STRING String);
ULONG __fastcall RtlGetCurrentServiceSessionId(VOID);
extern "C" __int64 __fastcall ZwSystemDebugControl();
extern "C" __int64 __fastcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
USHORT __fastcall LdrpGetBaseNameFromFullName(PUNICODE_STRING BaseName, PUNICODE_STRING FullName);
//NTSTATUS __fastcall LdrpThreadTokenSetMainThreadToken();

// Planning to implement them all in the future.
typedef NTSTATUS(__fastcall* tNtOpenThreadToken)(IN HANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN BOOLEAN OpenAsSelf, OUT PHANDLE TokenHandle);
extern	tNtOpenThreadToken NtOpenThreadToken;

typedef NTSTATUS(__fastcall* tNtClose)(HANDLE Handle);
extern	tNtClose NtClose;

typedef PVOID(__fastcall* tRtlAllocateHeap)(IN PVOID HeapHandle, IN OPTIONAL ULONG Flags, IN SIZE_T Size);
extern	tRtlAllocateHeap RtlAllocateHeap;

typedef BOOLEAN(__fastcall* tRtlFreeHeap)(IN PVOID HeapHandle, IN OPTIONAL ULONG Flags, _Frees_ptr_opt_ PVOID BaseAddress);
extern	tRtlFreeHeap RtlFreeHeap;

typedef NTSTATUS(__fastcall* tLdrGetDllPath)(PWCH DllName, DWORD dwFlags, PWSTR* Path, PWSTR* Unknown);
extern	tLdrGetDllPath LdrGetDllPath;

typedef VOID(__fastcall* tRtlReleasePath)(IN PWSTR);
extern	tRtlReleasePath RtlReleasePath;

typedef NTSTATUS(__fastcall* tRtlInitUnicodeStringEx)(PUNICODE_STRING target, PCWSTR source);
extern	tRtlInitUnicodeStringEx RtlInitUnicodeStringEx;

typedef NTSTATUS(__fastcall* tRtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
extern	tRtlEnterCriticalSection RtlEnterCriticalSection;

typedef NTSTATUS(__fastcall* tRtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
extern	tRtlLeaveCriticalSection RtlLeaveCriticalSection;

typedef NTSTATUS(__fastcall* tZwSetEvent)(HANDLE EventHandle, PLONG PreviousState);
extern	tZwSetEvent ZwSetEvent;

typedef NTSTATUS(__fastcall* tNtOpenFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
extern tNtOpenFile NtOpenFile;

typedef NTSTATUS(__fastcall* tLdrAppxHandleIntegrityFailure)(NTSTATUS Status);
extern tLdrAppxHandleIntegrityFailure LdrAppxHandleIntegrityFailure;

typedef NTSTATUS(__fastcall* tNtRaiseHardError)(NTSTATUS Status, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, INT* Parameters, HARDERROR_RESPONSE_OPTION ValidResponseOption, HARDERROR_RESPONSE* Response);
extern tNtRaiseHardError NtRaiseHardError;


#define LDRP_LOG_INTERNAL_PATTERN "\x89\x54\x24\x10\x4C\x8B\xDC\x49\x89\x4B\x08"
typedef NTSTATUS(__fastcall* tLdrpLogInternal)(PCHAR, ULONG, PCHAR, ULONG, PCHAR, ...);
extern	tLdrpLogInternal LdrpLogInternal;

#define LDRP_INITIALIZE_DLLPATH_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x49\x8B\xF8\x48\x8B\xDA\x48\x8B\xF1"
typedef NTSTATUS(__fastcall* tLdrpInitializeDllPath)(PWSTR DllName, PWSTR DllPath, LDR_UNKSTRUCT* ReturnPath);
extern	tLdrpInitializeDllPath LdrpInitializeDllPath;

#define LDRP_DEREFERENCE_MODULE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x48\x8B\x81\x98\x00\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpDereferenceModule)(LDR_DATA_TABLE_ENTRY* DllEntry);
extern	tLdrpDereferenceModule LdrpDereferenceModule;

#define LDRP_LOG_DLLSTATE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x41"
typedef NTSTATUS(__fastcall* tLdrpLogDllState)(ULONG, PUNICODE_STRING, ULONG);
extern	tLdrpLogDllState LdrpLogDllState;

#define LDRP_PREPROCESS_DLLNAME_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x6B\x10\x49\x89\x73\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x40"
typedef NTSTATUS(__fastcall* tLdrpPreprocessDllName)(PUNICODE_STRING DllName, PUNICODE_STRING ResName, PULONG pZero, PULONG pFlags);
extern	tLdrpPreprocessDllName LdrpPreprocessDllName;

#define LDRP_FASTPTH_RELOADED_DLL_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x83\x64\x24\x48\x00"
typedef NTSTATUS(__fastcall* tLdrpFastpthReloadedDll)(PUNICODE_STRING FullPath, ULONG Flags, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry);
extern	tLdrpFastpthReloadedDll LdrpFastpthReloadedDll;

#define LDRP_DRAIN_WORKQUEUE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x56\x48\x83\xEC\x20\x4C\x8B\x35\x35\xA3\x15\x00"
typedef TEB* (__fastcall* tLdrpDrainWorkQueue)(DRAIN_TASK DrainTask);
extern	tLdrpDrainWorkQueue LdrpDrainWorkQueue;

#define LDRP_FIND_LOADEDDLL_BYHANDLE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x18\x41\x56\x48\x83\xEC\x20\x33\xDB\x49\x8B\xF8\x4C\x8B\xF2"
typedef NTSTATUS(__fastcall* tLdrpFindLoadedDllByHandle)(unsigned __int64 a1, PLDR_DATA_TABLE_ENTRY* ppLdrEntry, DWORD* a3);
extern	tLdrpFindLoadedDllByHandle LdrpFindLoadedDllByHandle;

#define LDRP_DROP_LASTINPROGRESS_COUNT_PATTERN "\x48\x83\xEC\x28\x65\x48\x8B\x04\x25\x30\x00\x00\x00\xB9\xFF\xEF\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpDropLastInProgressCount)();
extern	tLdrpDropLastInProgressCount LdrpDropLastInProgressCount;

#define LDRP_QUERY_CURRENT_PATCH_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x20\x55\x41\x56"
typedef NTSTATUS(__fastcall* tLdrpQueryCurrentPatch)(ULONG Checksum, ULONG TimeDateStamp, PUNICODE_STRING FullPath);
extern	tLdrpQueryCurrentPatch LdrpQueryCurrentPatch;

#define LDRP_UNDO_PATCH_IMAGE_PATTERN "\x4C\x8B\xDC\x53\x48\x83\xEC\x40\x48\x8B\x41\x30\x4D\x8D\x4B\x08"
typedef NTSTATUS(__fastcall* tLdrpUndoPatchImage)(PLDR_DATA_TABLE_ENTRY LdrEntry);
extern	tLdrpUndoPatchImage LdrpUndoPatchImage;

#define LDRP_DETECT_DETOUR_PATTERN "\x40\x57\x48\x83\xEC\x30\x80\x3D\x87\x32\x11\x00\x00\x75\x7B"
typedef VOID(__fastcall* tLdrpDetectDetour)();
extern	tLdrpDetectDetour LdrpDetectDetour;

#define LDRP_FINDORPREPARE_LOADINGMODULE_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x20\x57\x41\x56\x41\x57\x48\x83\xEC\x50"
typedef NTSTATUS(__fastcall* tLdrpFindOrPrepareLoadingModule)(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY* pLdrEntryLoaded, NTSTATUS* pStatus);
extern	tLdrpFindOrPrepareLoadingModule LdrpFindOrPrepareLoadingModule;

#define LDRP_FREE_LOAD_CONTEXT_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x41\x38\x48\x8B\xD9\x48\x83\xA0\xB0\x00\x00\x00"
typedef VOID(__fastcall* tLdrpFreeLoadContext)(PLDRP_LOAD_CONTEXT LoadContext);
extern	tLdrpFreeLoadContext LdrpFreeLoadContext;

#define LDRP_CONDENSE_GRAPH_PATTERN "\x48\x8B\xC4\x48\x83\xEC\x28\x83\x79\x38\x06\x7D\x19"
typedef PVOID* (__fastcall* tLdrpCondenseGraph)(LDR_DDAG_NODE* DdagNode);
extern	tLdrpCondenseGraph LdrpCondenseGraph;

#define LDRP_BUILD_FORWARDER_LINK_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x33\xDB\x48\x8B\xF2"
typedef NTSTATUS(__fastcall* tLdrpBuildForwarderLink)(PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2);
extern	tLdrpBuildForwarderLink LdrpBuildForwarderLink;

#define LDRP_PIN_MODULE_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\xD9\x33\xFF\x48\x8D\x0D\x02\xBB\x10\x00"
typedef NTSTATUS(__fastcall* tLdrpPinModule)(PLDR_DATA_TABLE_ENTRY LdrEntry);
extern tLdrpPinModule LdrpPinModule;

#define LDRP_APPLY_PATCH_IMAGE_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x7C\x24\x18\x55\x41\x56\x41\x57\x48\x8B\xEC"
typedef NTSTATUS(__fastcall* tLdrpApplyPatchImage)(PLDR_DATA_TABLE_ENTRY LdrEntry);
extern tLdrpApplyPatchImage LdrpApplyPatchImage;

#define LDRP_FREE_LOADCONTEXT_NODE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\x19\x48\x8B\xF2"
typedef NTSTATUS(__fastcall* tLdrpFreeLoadContextOfNode)(PLDR_DDAG_NODE DdagNode, NTSTATUS* pStatus);
extern tLdrpFreeLoadContextOfNode LdrpFreeLoadContextOfNode;

#define LDRP_DECREMENT_MODULELOADCOUNTEX_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x8B\xFA\x48\x8B\xD9\x85\xD2"
typedef NTSTATUS(__fastcall* tLdrpDecrementModuleLoadCountEx)(PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2);
extern tLdrpDecrementModuleLoadCountEx LdrpDecrementModuleLoadCountEx;

#define LDRP_LOG_ERROR_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x49\x8B\xD9"
typedef PEB*(__fastcall* tLdrpLogError)(NTSTATUS Status, ULONG, ULONG, PVOID);
extern tLdrpLogError LdrpLogError;

#define LDRP_LOG_DEPRECATED_DLL_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x6C\x24\x18\x48\x89\x74\x24\x20\x57\x48\x83\xEC\x40"
typedef WCHAR*(__fastcall* tLdrpLogDeprecatedDllEtwEvent)(PLDRP_LOAD_CONTEXT LoadContext);
extern tLdrpLogDeprecatedDllEtwEvent LdrpLogDeprecatedDllEtwEvent;

#define LDRP_LOG_LOAD_FAILURE_PATTERN "\x48\x89\x5C\x24\x08\x44\x89\x44\x24\x18\x55\x56\x57\x48\x8B\xEC\x48\x83\xEC\x70"
typedef VOID(__fastcall* tLdrpLogLoadFailureEtwEvent)(PVOID Unknown, PVOID Unknown2, NTSTATUS Status, PVOID LoadFailure, ULONG Unknown3);
extern tLdrpLogLoadFailureEtwEvent LdrpLogLoadFailureEtwEvent;

#define LDRP_REPORT_ERROR_PATTERN "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\x50\xFF\xFF\xFF\x48\x81\xEC\xB0\x01\x00\x00\x48\x8B\x05\xEE\x08\x19\x00"
typedef NTSTATUS(__fastcall* tLdrpReportError)(PLDRP_LOAD_CONTEXT LoadContext, ULONG Unknown, NTSTATUS Status);
extern tLdrpReportError LdrpReportError;

#define LDRP_RESOLVE_DLLNAME_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x6B\x10\x49\x89\x73\x20\x4D\x89\x43\x18\x57\x41\x54\x41\x55\x41\x56"
typedef NTSTATUS(__fastcall* tLdrpResolveDllName)(PLDRP_LOAD_CONTEXT FileName, LDRP_FILENAME_BUFFER* FileNameBuffer, PUNICODE_STRING FullName, PUNICODE_STRING ResolvedName, DWORD Flags);
extern tLdrpResolveDllName LdrpResolveDllName;

#define LDRP_APP_COMPAT_REDIRECT_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x83\xEC\x50\x45\x33\xFF\x49\x8B\xF1\x44\x38\x3D\xC3\x3A\x17\x00"
typedef NTSTATUS(__fastcall* tLdrpAppCompatRedirect)(PLDRP_LOAD_CONTEXT LoadContext, PUNICODE_STRING FullDllName, PUNICODE_STRING BaseDllName, LDRP_FILENAME_BUFFER* FileNameBuffer, NTSTATUS Status);
extern tLdrpAppCompatRedirect LdrpAppCompatRedirect;

#define LDRP_HASH_UNICODE_STRING_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x45\x33\xDB"
typedef DWORD(__fastcall* tLdrpHashUnicodeString)(PUNICODE_STRING BaseDllName);
extern tLdrpHashUnicodeString LdrpHashUnicodeString;

#define LDRP_FIND_EXISTING_MODULE_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x30\x48\x8B\x7C\x24\x60\x48\x8B\xD9"
typedef NTSTATUS(__fastcall* tLdrpFindExistingModule)(PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, UINT64 Flags, DWORD BaseDllNameHash, PLDR_DATA_TABLE_ENTRY* LoadedDll);
extern tLdrpFindExistingModule LdrpFindExistingModule;

#define LDRP_LOADCONTEXT_REPLACE_MODULE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x48\x8B\xD9\x48\x8B\xF2"
typedef NTSTATUS(__fastcall* tLdrpLoadContextReplaceModule)(PLDRP_LOAD_CONTEXT LoadContext, PLDR_DATA_TABLE_ENTRY LoadedDll);
extern tLdrpLoadContextReplaceModule LdrpLoadContextReplaceModule;

#define LDRP_CHECKFORRETRY_LOADING_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x33\xDB\x44\x8A\xFA"
typedef BOOLEAN(__fastcall* tLdrpCheckForRetryLoading)(PLDRP_LOAD_CONTEXT LoadContext, BOOLEAN Unknown);
extern tLdrpCheckForRetryLoading LdrpCheckForRetryLoading;

#define LDRP_LOG_ETWEVENT_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x80\x02\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpLogEtwEvent)(ULONG a1, ULONGLONG a2, ULONG a3, ULONG a4);
extern tLdrpLogEtwEvent LdrpLogEtwEvent;

#define LDRP_CHECK_COMPONENTONDEMAND_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56\x48\x8B\xEC\x48\x81\xEC\x80\x00\x00\x00"
typedef BOOLEAN(__fastcall* tLdrpCheckComponentOnDemandEtwEvent)(PUSHORT Length);
extern tLdrpCheckComponentOnDemandEtwEvent LdrpCheckComponentOnDemandEtwEvent;

#define LDRP_VALIDATE_INTEGRITY_PATTERN "\x44\x88\x44\x24\x18\x53\x56\x57\x48\x83\xEC\x30"
typedef NTSTATUS(__fastcall* tLdrpValidateIntegrityContinuity)(PLDRP_LOAD_CONTEXT LoadContext, HANDLE FileHandle);
extern tLdrpValidateIntegrityContinuity LdrpValidateIntegrityContinuity;

#define LDRP_SET_MODULE_SIGNINGLEVEL_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x10\x49\x89\x73\x18\x49\x89\x7B\x20\x49\x89\x4B\x08\x41\x56"
typedef NTSTATUS(__fastcall* tLdrpSetModuleSigningLevel)(HANDLE FileHandle, PLDR_DATA_TABLE_ENTRY LoadContext, PULONG pSigningLevel, ULONG NewSigningLevelMaybe);
extern tLdrpSetModuleSigningLevel LdrpSetModuleSigningLevel;

#define LDRP_CODE_AUTHZCHECKDLL_ALLOWED_PATTERN "\x48\x83\x3D\xC8\x44\x17\x00\x00\x4C\x8B\xCA"
typedef NTSTATUS(__fastcall* tLdrpCodeAuthzCheckDllAllowed)(PUNICODE_STRING pFileNameBuffer, HANDLE FileHandle);
extern tLdrpCodeAuthzCheckDllAllowed LdrpCodeAuthzCheckDllAllowed;

#define LDRP_GET_FULLPATH_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x08\x55\x56\x57\x41\x56\x41\x57\x48\x83\xEC\x30"
typedef NTSTATUS(__fastcall* tLdrpGetFullPath)(PLDRP_LOAD_CONTEXT LoadContext, PUNICODE_STRING FullPath);
extern tLdrpGetFullPath LdrpGetFullPath;

#define LDRP_ALLOCATE_UNICODESTRING_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x33\xDB\x8D\x7A\x02"
typedef NTSTATUS(__fastcall* tLdrpAllocateUnicodeString)(PUNICODE_STRING Allocated, USHORT Length);
extern tLdrpAllocateUnicodeString LdrpAllocateUnicodeString;

#define LDRP_APPEND_UNICODETOFILENAME_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x20\x45\x33\xF6\x48\x8B\xEA"
typedef NTSTATUS(__fastcall* tLdrpAppendUnicodeStringToFilenameBuffer)(PUSHORT pLength, PLDRP_LOAD_CONTEXT LoadContext);
extern tLdrpAppendUnicodeStringToFilenameBuffer LdrpAppendUnicodeStringToFilenameBuffer;

#define LDRP_GET_NTPATH_FROM_DOSPATH_PATTERN "\x48\x89\x5C\x24\x18\x55\x56\x57\x48\x8D\x6C\x24\xB9\x48\x81\xEC\xC0\x00\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpGetNtPathFromDosPath)(PUNICODE_STRING DosPath, LDRP_FILENAME_BUFFER* NtPath);
extern tLdrpGetNtPathFromDosPath LdrpGetNtPathFromDosPath;