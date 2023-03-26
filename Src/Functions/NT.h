#pragma once

#include "..\Includes.h"
#include "..\WID.h"
#include "Undocumented.h"


#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_SUCCESS						0x0
#define STATUS_UNSUCCESSFUL					0xC0000001
#define STATUS_NO_SUCH_FILE					0xC000000F
#define STATUS_NO_TOKEN						0xC000007C
#define STATUS_NO_APPLICATION_PACKAGE		0xC00001AA
#define STATUS_RETRY						0xC000022D
#define STATUS_PATCH_CONFLICT				0xC00004AC
#define STATUS_IMAGE_LOADED_AS_PATCH_IMAGE	0xC00004C0
#define STATUS_INVALID_THREAD				0xC000071C

// Implemented.
extern HANDLE* LdrpMainThreadToken;
extern DWORD* LdrInitState;

PEB* NtCurrentPeb();
VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer);
VOID __fastcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
VOID __fastcall LdrpFreeUnicodeString(PUNICODE_STRING String);
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
typedef TEB* (__fastcall* tLdrpDrainWorkQueue)(BOOL IsLoadEvent);
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