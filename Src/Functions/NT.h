#pragma once

#include "..\Includes.h"
#include "..\WID.h"
#include "Undocumented.h"


#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS						0x0
#define STATUS_IMAGE_NOT_AT_BASE			0x40000003
#define STATUS_IMAGE_AT_DIFFERENT_BASE		0x40000036
#define STATUS_IMAGE_MACHINE_TYPE_MISMATCH	0x4000000E
#define STATUS_DEVICE_OFF_LINE				0x80000010
#define STATUS_UNSUCCESSFUL					0xC0000001
#define STATUS_NOT_IMPLEMENTED				0xC0000002
#define STATUS_NO_SUCH_FILE					0xC000000F
#define STATUS_CONFLICTING_ADDRESSES		0xC0000018
#define STATUS_ACCESS_DENIED				0xC0000022
#define STATUS_OBJECT_NAME_NOT_FOUND		0xC0000034
#define STATUS_OBJECT_PATH_NOT_FOUND		0xC000003A
#define STATUS_PROCEDURE_NOT_FOUND			0xC000007A
#define STATUS_DEVICE_NOT_READY				0xC00000A3
#define STATUS_INVALID_IMAGE_FORMAT			0xC000007B
#define STATUS_NO_TOKEN						0xC000007C
#define STATUS_INSUFFICIENT_RESOURCES		0xC000009A
#define STATUS_NOT_SUPPORTED				0xC00000BB
#define STATUS_INTERNAL_ERROR				0xC00000E5
#define STATUS_NAME_TOO_LONG				0xC0000106
#define STATUS_COMMITMENT_LIMIT				0xC000012D
#define STATUS_NO_APPLICATION_PACKAGE		0xC00001AA
#define STATUS_RESOURCE_LANG_NOT_FOUND		0xC0000204
#define STATUS_NOT_FOUND					0xC0000225
#define STATUS_RETRY						0xC000022D
#define STATUS_INVALID_IMAGE_HASH			0xC0000428
#define STATUS_NEEDS_REMEDIATION			0xC0000462
#define STATUS_PATCH_CONFLICT				0xC00004AC
#define STATUS_IMAGE_LOADED_AS_PATCH_IMAGE	0xC00004C0
#define STATUS_INVALID_THREAD				0xC000071C


// Implemented.
extern DWORD*					LdrpPolicyBits;
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
extern PRTL_SRWLOCK				LdrpModuleDatatableLock;
extern PHANDLE					qword_17E238;
extern LDR_DATA_TABLE_ENTRY**	LdrpImageEntry;
extern PUNICODE_STRING			LdrpKernel32DllName;
extern UINT_PTR*				LdrpAppHeaders;
extern PHANDLE					LdrpLargePageDllKeyHandle;
extern ULONG**					LdrpLockMemoryPrivilege;
extern ULONG64*					LdrpMaximumUserModeAddress;
extern UINT_PTR*				LdrpMapAndSnapWork;
extern LIST_ENTRY*				LdrpHashTable;
extern PVOID*					LdrpHeap;
extern BOOLEAN*					LdrpIsHotPatchingEnabled;
extern LDR_DATA_TABLE_ENTRY**	LdrpRedirectionModule;
extern ULONG64**				qword_1993A8;
extern LONG*					NtdllBaseTag;
extern UINT_PTR**				xmmword_199520;
extern UINT_PTR*				qword_199530;
extern LDR_DATA_TABLE_ENTRY**	LdrpNtDllDataTableEntry;
extern UINT_PTR*				qword_1993B8;
extern DWORD*					dword_19939C;
extern DWORD*					LoadFailureOperational;
extern DWORD*					dword_199398;
extern UINT_PTR***				qword_1843B8;
extern UINT_PTR*				qword_1843B0;
extern UINT_PTR*				LdrpCurrentDllInitializer;
extern LPVOID**					LdrpProcessInitContextRecord;

typedef NTSTATUS(__fastcall** tLdrpManifestProberRoutine)(PIMAGE_DOS_HEADER Base, PWCHAR, PVOID);
extern tLdrpManifestProberRoutine LdrpManifestProberRoutine;
typedef BOOLEAN(__fastcall** tLdrpRedirectionCalloutFunc)(PWCHAR Buffer);
extern tLdrpRedirectionCalloutFunc LdrpRedirectionCalloutFunc;


PEB* NtCurrentPeb();
VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer);
VOID __fastcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
VOID __fastcall LdrpFreeUnicodeString(PUNICODE_STRING String);
ULONG __fastcall RtlGetCurrentServiceSessionId(VOID);
USHORT __fastcall LdrpGetBaseNameFromFullName(PUNICODE_STRING BaseName, PUNICODE_STRING FullName);
PWCHAR __fastcall RtlGetNtSystemRoot();
BOOLEAN __fastcall LdrpHpatAllocationOptOut(PUNICODE_STRING FullDllName);
NTSTATUS __fastcall LdrpCorValidateImage(PIMAGE_DOS_HEADER DosHeader);
NTSTATUS __fastcall LdrpCorFixupImage(PIMAGE_DOS_HEADER DosHeader);
NTSTATUS __fastcall LdrpFindLoadedDllByNameLockHeld(PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, ULONG64 Flags, LDR_DATA_TABLE_ENTRY** pLdrEntry, ULONG BaseNameHashValue);
BOOLEAN __fastcall LdrpIsILOnlyImage(PIMAGE_DOS_HEADER DllBase);
VOID __fastcall LdrpAddNodeServiceTag(LDR_DDAG_NODE* DdagNode, UINT_PTR ServiceTag);
NTSTATUS __fastcall LdrpFindDllActivationContext(LDR_DATA_TABLE_ENTRY* LdrEntry);
PIMAGE_LOAD_CONFIG_DIRECTORY LdrImageDirectoryEntryToLoadConfig(PIMAGE_DOS_HEADER DllBase);
BOOLEAN __fastcall LdrpShouldModuleImportBeRedirected(LDR_DATA_TABLE_ENTRY* DllEntry);
PIMAGE_IMPORT_DESCRIPTOR __fastcall LdrpGetImportDescriptorForSnap(LDRP_LOAD_CONTEXT* LoadContext);
NTSTATUS __fastcall LdrpMapCleanModuleView(LDRP_LOAD_CONTEXT* LoadContext);
LDR_DATA_TABLE_ENTRY* __fastcall LdrpHandleReplacedModule(LDR_DATA_TABLE_ENTRY* LdrEntry);
NTSTATUS __fastcall LdrpFreeReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry);
VOID __fastcall LdrpHandlePendingModuleReplaced(LDRP_LOAD_CONTEXT* LoadContext);
PIMAGE_SECTION_HEADER __fastcall RtlSectionTableFromVirtualAddress(PIMAGE_NT_HEADERS NtHeader, PVOID Base, UINT_PTR Address);
PIMAGE_SECTION_HEADER __fastcall RtlAddressInSectionTable(PIMAGE_NT_HEADERS NtHeader, PVOID Base, UINT_PTR Address);
BOOLEAN __fastcall LdrpValidateEntrySection(LDR_DATA_TABLE_ENTRY* DllEntry);
BOOL __fastcall LdrpIsExecutableRelocatedImage(PIMAGE_DOS_HEADER DllBase);
NTSTATUS __fastcall LdrpInitializeGraphRecurse(LDR_DDAG_NODE* DdagNode, NTSTATUS* pStatus, char* Unknown);
NTSTATUS __fastcall LdrpInitializeNode(_LDR_DDAG_NODE* DdagNode);
BOOLEAN __fastcall LdrpCallInitRoutine(BOOL(__fastcall* DllMain)(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved), PIMAGE_DOS_HEADER DllBase, unsigned int One, LPVOID ContextRecord);

extern "C" NTSTATUS __fastcall ZwSystemDebugControl();
extern "C" NTSTATUS __fastcall NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES * ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
extern "C" NTSTATUS __fastcall ZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PIMAGE_DOS_HEADER * BaseAddress, ULONG64 ZeroBits, ULONG64 CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG64 AllocationType, ULONG64 Protect);
extern "C" NTSTATUS __fastcall ZwMapViewOfSectionEx(HANDLE SectionHandle, HANDLE ProcessHandle, PIMAGE_DOS_HEADER * DllBase, PLARGE_INTEGER a4, PULONG ViewSize, ULONG a6, ULONG a7, MEM_EXTENDED_PARAMETER * MemExtendedParam, ULONG a9);
extern "C" NTSTATUS __fastcall NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);
extern "C" NTSTATUS __fastcall ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
extern "C" NTSTATUS __fastcall ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
extern "C" NTSTATUS __fastcall NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

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

typedef NTSTATUS(__fastcall* tRtlImageNtHeaderEx)(ULONG Flags, PVOID Base, ULONG64 Size, PIMAGE_NT_HEADERS* OutHeaders);
extern tRtlImageNtHeaderEx RtlImageNtHeaderEx;

typedef VOID(__fastcall* tRtlAcquireSRWLockExclusive)(PRTL_SRWLOCK SRWLock);
extern tRtlAcquireSRWLockExclusive RtlAcquireSRWLockExclusive;

typedef NTSTATUS(__fastcall* tRtlReleaseSRWLockExclusive)(PRTL_SRWLOCK SRWLock);
extern tRtlReleaseSRWLockExclusive RtlReleaseSRWLockExclusive;

typedef NTSTATUS(__fastcall* tRtlEqualUnicodeString)(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSensitive);
extern tRtlEqualUnicodeString RtlEqualUnicodeString;

typedef NTSTATUS(__fastcall* tRtlAcquirePrivilege)(ULONG* Privilege,ULONG NumPriv,ULONG Flags,PVOID * ReturnedState);
extern tRtlAcquirePrivilege RtlAcquirePrivilege;

typedef VOID(__fastcall* tRtlReleasePrivilege)(PVOID ReturnedState);
extern tRtlReleasePrivilege RtlReleasePrivilege;

typedef NTSTATUS(__fastcall* tRtlCompareUnicodeStrings)(PWCH String1, UINT_PTR String1Length, PWCH String2, UINT_PTR String2Length, BOOLEAN CaseInSensitive);
extern tRtlCompareUnicodeStrings RtlCompareUnicodeStrings;

typedef PIMAGE_NT_HEADERS(__fastcall* tRtlImageNtHeader)(PIMAGE_DOS_HEADER DosHeader);
extern tRtlImageNtHeader RtlImageNtHeader;

typedef UINT_PTR(__fastcall* tRtlReleaseActivationContext)(ACTIVATION_CONTEXT* ActivationContext);
extern tRtlReleaseActivationContext RtlReleaseActivationContext;

typedef NTSTATUS(__fastcall* tRtlCharToInteger)(const PCHAR String, ULONG Base, PULONG Value);
extern tRtlCharToInteger RtlCharToInteger;

typedef NTSTATUS(__fastcall* tRtlActivateActivationContextUnsafeFast)(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED* StackFrameExtended, ACTIVATION_CONTEXT* ActivationContext);
extern tRtlActivateActivationContextUnsafeFast RtlActivateActivationContextUnsafeFast;

typedef VOID(__fastcall* tRtlDeactivateActivationContextUnsafeFast)(RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED* StackFrameExtended);
extern tRtlDeactivateActivationContextUnsafeFast RtlDeactivateActivationContextUnsafeFast;

// Signatured
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
typedef NTSTATUS(__fastcall* tLdrpReportError)(PVOID Report, ULONG Unknown, NTSTATUS Status);
extern tLdrpReportError LdrpReportError;

#define LDRP_RESOLVE_DLLNAME_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x6B\x10\x49\x89\x73\x20\x4D\x89\x43\x18\x57\x41\x54\x41\x55\x41\x56"
typedef NTSTATUS(__fastcall* tLdrpResolveDllName)(PLDRP_LOAD_CONTEXT FileName, LDRP_FILENAME_BUFFER* FileNameBuffer, PUNICODE_STRING FullName, PUNICODE_STRING ResolvedName, DWORD Flags);
extern tLdrpResolveDllName LdrpResolveDllName;

#define LDRP_APP_COMPAT_REDIRECT_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x83\xEC\x50\x45\x33\xFF\x49\x8B\xF1\x44\x38\x3D\xC3\x3A\x17\x00"
typedef NTSTATUS(__fastcall* tLdrpAppCompatRedirect)(PLDRP_LOAD_CONTEXT LoadContext, PUNICODE_STRING FullDllName, PUNICODE_STRING BaseDllName, LDRP_FILENAME_BUFFER* FileNameBuffer, NTSTATUS Status);
extern tLdrpAppCompatRedirect LdrpAppCompatRedirect;

#define LDRP_HASH_UNICODE_STRING_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x45\x33\xDB"
typedef ULONG(__fastcall* tLdrpHashUnicodeString)(PUNICODE_STRING BaseDllName);
extern tLdrpHashUnicodeString LdrpHashUnicodeString;

#define LDRP_FIND_EXISTING_MODULE_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x30\x48\x8B\x7C\x24\x60\x48\x8B\xD9"
typedef NTSTATUS(__fastcall* tLdrpFindExistingModule)(PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, UINT64 Flags, ULONG BaseDllNameHash, PLDR_DATA_TABLE_ENTRY* LoadedDll);
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
typedef BOOLEAN(__fastcall* tLdrpCheckComponentOnDemandEtwEvent)(PUNICODE_STRING Component);
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

#define LDRP_FIND_LOADEDDLL_MAPLOCK_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x83\xEC\x30\x4C\x8B\x15\xFD\x89\x15\x00"
typedef NTSTATUS(__fastcall* tLdrpFindLoadedDllByMappingLockHeld)(PIMAGE_DOS_HEADER DllBase, PIMAGE_NT_HEADERS OutHeaders, PVOID Unknown, PLDR_DATA_TABLE_ENTRY* pLdrEntry);
extern tLdrpFindLoadedDllByMappingLockHeld LdrpFindLoadedDllByMappingLockHeld;

#define LDRP_INSERT_DATATABLEENTRY_PATTERN "\x40\x53\x48\x83\xEC\x20\xF6\x41\x68\x40"
typedef VOID(__fastcall* tLdrpInsertDataTableEntry)(PLDR_DATA_TABLE_ENTRY LdrEntry);
extern tLdrpInsertDataTableEntry LdrpInsertDataTableEntry;

#define LDRP_INSERT_MODTOIDX_LOCKHELD_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x44\x8B\x4A\x08"
typedef NTSTATUS(__fastcall* tLdrpInsertModuleToIndexLockHeld)(PLDR_DATA_TABLE_ENTRY LdrEntry, PIMAGE_NT_HEADERS OutHeaders);
extern tLdrpInsertModuleToIndexLockHeld LdrpInsertModuleToIndexLockHeld;

#define LDRP_LOGETW_HOTPATCHSTATUS_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18\x4C\x89\x60\x20\x55\x41\x56\x41\x57\x48\x8D\x68\x98"
typedef NTSTATUS(__fastcall* tLdrpLogEtwHotPatchStatus)(PUNICODE_STRING BaseDllName, LDR_DATA_TABLE_ENTRY* LdrEntry, PUNICODE_STRING FullDllName, NTSTATUS Status, ULONG Unknown);
extern tLdrpLogEtwHotPatchStatus LdrpLogEtwHotPatchStatus;

#define LDRP_LOG_NEWDLL_LOAD_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x30\x48\x8B\xEA\x4C\x8B\xF1"
typedef PEB*(__fastcall* tLdrpLogNewDllLoad)(LDR_DATA_TABLE_ENTRY* LdrEntry, LDR_DATA_TABLE_ENTRY* LdrEntry2);
extern tLdrpLogNewDllLoad LdrpLogNewDllLoad;

#define LDRP_PROCESS_MACHINE_MISMATCH_PATTERN "\x40\x53\x55\x57\x48\x83\xEC\x40\x48\x8B\x59\x38"
typedef NTSTATUS(__fastcall* tLdrpProcessMachineMismatch)(PLDRP_LOAD_CONTEXT LoadContext);
extern tLdrpProcessMachineMismatch LdrpProcessMachineMismatch;

#define RTL_QUERY_IMAGEFILE_KEYOPT_PATTERN "\x48\x89\x5C\x24\x10\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\xAC\x24\xA0\xFC\xFF\xFF"
typedef NTSTATUS(__fastcall* tRtlQueryImageFileKeyOption)(HANDLE hKey, PCWSTR lpszOption, ULONG dwType, PVOID lpData, ULONG cbData, ULONG* lpcbData);
extern tRtlQueryImageFileKeyOption RtlQueryImageFileKeyOption;

#define RTLP_IMAGEDIR_ENTRYTODATA_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x10\x49\x89\x6B\x18\x49\x89\x73\x20\x57\x41\x56\x41\x57\x48\x83\xEC\x20\x4C\x8B\x74\x24\x60"
typedef NTSTATUS(__fastcall* tRtlpImageDirectoryEntryToDataEx)(PIMAGE_DOS_HEADER DllBase, BOOLEAN Unknown, WORD Characteristics, ULONG64* LastRVASection, PVOID OutHeader);
extern tRtlpImageDirectoryEntryToDataEx RtlpImageDirectoryEntryToDataEx;

#define LDRP_LOG_DLLRELOCATION_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x4D\x8B\xF1"
typedef PVOID(__fastcall* tLdrpLogDllRelocationEtwEvent)(PUNICODE_STRING FullDllName, ULONGLONG ImageBase, PIMAGE_DOS_HEADER DllBase, SIZE_T Size);
extern tLdrpLogDllRelocationEtwEvent LdrpLogDllRelocationEtwEvent;

#define LDRP_NOTIFY_LOADOFGRAPH_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x20\x48\x8B\x71\x28\x48\x8B\xF9"
typedef NTSTATUS(__fastcall* tLdrpNotifyLoadOfGraph)(LDR_DDAG_NODE* DdagNode);
extern tLdrpNotifyLoadOfGraph LdrpNotifyLoadOfGraph;

#define LDRP_DYNAMIC_SHIMMODULE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x18\x48\x89\x74\x24\x20\x57\x41\x56\x41\x57\x48\x83\xEC\x40"
typedef NTSTATUS(__fastcall* tLdrpDynamicShimModule)(LDR_DDAG_NODE* DdagNode);
extern tLdrpDynamicShimModule LdrpDynamicShimModule;

#define LDRP_ACQUIRE_LOADERLOCK_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\xE8\xE4\x9E\xFE\xFF"
typedef NTSTATUS(__fastcall* tLdrpAcquireLoaderLock)();
extern tLdrpAcquireLoaderLock LdrpAcquireLoaderLock;

#define LDRP_RELEASE_LOADER_LOCK_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x30\x48\x8D\x0D\x2E\xD8\x12\x00"
typedef NTSTATUS(__fastcall* tLdrpReleaseLoaderLock)(ULONG64 Unused, ULONG Two, ULONG64 LdrFlags);
extern tLdrpReleaseLoaderLock LdrpReleaseLoaderLock;

#define LDRP_CHECKPAGES_FOR_TAMPERING_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x30\x48\x8D\xBA\xFF\x0F\x00\x00"
typedef BOOLEAN(__fastcall* tLdrpCheckPagesForTampering)(PIMAGE_DATA_DIRECTORY pDataDir, ULONG64 Offset);
extern tLdrpCheckPagesForTampering LdrpCheckPagesForTampering;

#define LDRP_LOAD_DEPENDENTMODULEA_PATTERN "\x4C\x8B\xDC\x55\x53\x49\x8D\xAB\x48\xFF\xFF\xFF"
typedef NTSTATUS(__fastcall* tLdrpLoadDependentModuleA)(PUNICODE_STRING SourceString, LDRP_LOAD_CONTEXT* LoadContext, LDR_DATA_TABLE_ENTRY* LdrEntry, UINT_PTR Unknown, LDR_DATA_TABLE_ENTRY** pLdrEntry, UINT_PTR Unknown2);
extern tLdrpLoadDependentModuleA LdrpLoadDependentModuleA;

#define LDRP_LOAD_DEPENDENTMODULEW_PATTERN "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x50\x01\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpLoadDependentModuleW)(PUNICODE_STRING SourceString, LDRP_LOAD_CONTEXT* LoadContext, LDR_DATA_TABLE_ENTRY* DllEntry);
extern tLdrpLoadDependentModuleW LdrpLoadDependentModuleW;

#define LDRP_QUEUE_WORK_PATTERN "\x40\x53\x48\x83\xEC\x20\x48\x8B\x41\x28\x48\x8B\xD9"
typedef NTSTATUS(__fastcall* tLdrpQueueWork)(PLDRP_LOAD_CONTEXT LoadContext);
extern tLdrpQueueWork LdrpQueueWork;

#define LDRP_HANDLE_TLSDATA_PATTERN "\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x48\x89\x7C\x24\x20\x41\x55\x41\x56\x41\x57\x48\x81\xEC\x00\x01\x00\x00"
typedef NTSTATUS(__fastcall* tLdrpHandleTlsData)(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry);
extern tLdrpHandleTlsData LdrpHandleTlsData;

#define LDR_CONTROLFLOWGUARD_ENFEXP_PATTERN "\x33\xC0\x48\x39\x05\x8F\x7D\x17\x00"
typedef BOOLEAN(__fastcall* tLdrControlFlowGuardEnforcedWithExportSuppression)();
extern tLdrControlFlowGuardEnforcedWithExportSuppression LdrControlFlowGuardEnforcedWithExportSuppression;

#define LDRP_UNSUPPRESS_ADDRESSIAT_PATTERN "\x48\x89\x5C\x24\x18\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x70\x48\x8B\x05\x6E\xC6\x0B\x00"
typedef __int64(__fastcall* tLdrpUnsuppressAddressTakenIat)(PIMAGE_DOS_HEADER DllBase, ULONG Unknown, ULONG Unknown2);
extern tLdrpUnsuppressAddressTakenIat LdrpUnsuppressAddressTakenIat;

#define LDR_CONTROLFLOWGUARD_ENF_PATTERN "\x48\x83\x3D\x90\xD5\x16\x00\x00"
typedef BOOL(__fastcall* tLdrControlFlowGuardEnforced)();
extern tLdrControlFlowGuardEnforced LdrControlFlowGuardEnforced;

#define RTLP_LOOKUP_FUNCTIONTABLE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x18\x48\x89\x7C\x24\x20\x41\x56\x48\x83\xEC\x20\x33\xDB"
typedef PIMAGE_RUNTIME_FUNCTION_ENTRY(__fastcall* tRtlpxLookupFunctionTable)(PIMAGE_DOS_HEADER DllBase, PIMAGE_RUNTIME_FUNCTION_ENTRY* ppImageFunctionEntry);
extern tRtlpxLookupFunctionTable RtlpxLookupFunctionTable;

#define LDRP_CHECK_REDIRECTION_PATTERN "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18\x4C\x89\x68\x20\x55\x41\x56\x41\x57\x48\x8D\x68\xA1"
typedef PCHAR(__fastcall* tLdrpCheckRedirection)(LDR_DATA_TABLE_ENTRY* DllEntry, LDR_DATA_TABLE_ENTRY* NtLdrEntry, PCHAR StringToBeHashed);
extern tLdrpCheckRedirection LdrpCheckRedirection;

#define COMPAT_CACHE_LOOKUPCDB_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x81\xEC\xB0\x01\x00\x00"
typedef BOOL(__fastcall* tCompatCachepLookupCdb)(PWCHAR Buffer, LONG Unknown);
extern tCompatCachepLookupCdb CompatCachepLookupCdb;

#define LDRP_GEN_RANDOM_PATTERN "\x48\x83\xEC\x28\xB9\x1C\x00\x00\x00\xE8\x0E\x0B\x00\x00"
typedef UINT_PTR(__fastcall* tLdrpGenRandom)();
extern tLdrpGenRandom LdrpGenRandom;

#define LDR_INIT_SECURITY_COOKIE_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x20\x55\x41\x54\x41\x56"
typedef BOOL(__fastcall* tLdrInitSecurityCookie)(PIMAGE_DOS_HEADER DllBase, INT_PTR ImageSize, UINT_PTR* Zero, UINT_PTR RandomNumberStuff, UINT_PTR* Zero_2);
extern tLdrInitSecurityCookie LdrInitSecurityCookie;

#define LDRP_CFG_PROCESS_LOADCFG_PATTERN "\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8D\x6C\x24\xD9\x48\x81\xEC\xF0\x00\x00\x00\x48\x8B\x05\x99\x11\x17\x00"
typedef NTSTATUS(__fastcall* tLdrpCfgProcessLoadConfig)(LDR_DATA_TABLE_ENTRY* DllEntry, PIMAGE_NT_HEADERS NtHeader, __int64 Zero);
extern tLdrpCfgProcessLoadConfig LdrpCfgProcessLoadConfig;

#define RTL_INSERT_INV_FUNCTIONTABLE_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x30\x8B\xDA\x4C\x8D\x44\x24\x50"
typedef NTSTATUS(__fastcall* tRtlInsertInvertedFunctionTable)(PIMAGE_DOS_HEADER DllBase, ULONG ImageSize);
extern tRtlInsertInvertedFunctionTable RtlInsertInvertedFunctionTable;

#define LDRP_SIGNAL_MODULEMAPPED_PATTERN "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x48\x8B\x81\x98\x00\x00\x00\x48\x8B\x78\x30"
typedef LDR_DDAG_NODE*(__fastcall* tLdrpSignalModuleMapped)(LDR_DATA_TABLE_ENTRY* DllEntry);
extern tLdrpSignalModuleMapped LdrpSignalModuleMapped;

#define AVRF_DLL_LOADNOTIFICATION_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
typedef NTSTATUS(__fastcall* tAVrfDllLoadNotification)(LDR_DATA_TABLE_ENTRY* DllEntry);
extern tAVrfDllLoadNotification AVrfDllLoadNotification;

#define LDRP_SEND_DLLNOTIFICATIONS_PATTERN "\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x73\x10\x57\x48\x83\xEC\x50\x83\x64\x24\x20\x00"
typedef NTSTATUS(__fastcall* tLdrpSendDllNotifications)(LDR_DATA_TABLE_ENTRY* DllEntry, UINT_PTR Unknown);
extern tLdrpSendDllNotifications LdrpSendDllNotifications;

#define LDRP_CALL_TLSINIT_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x48\x89\x7C\x24\x20\x41\x56\x48\x83\xEC\x60"
typedef NTSTATUS(__fastcall* tLdrpCallTlsInitializers)(ULONG One, LDR_DATA_TABLE_ENTRY* LdrEntry);
extern tLdrpCallTlsInitializers LdrpCallTlsInitializers;