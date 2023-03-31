#pragma once

#include "..\WID.h"

#define LLEXW_ISDATAFILE	(LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE)
#define LLEXW_7F08			(LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER | LOAD_LIBRARY_SAFE_CURRENT_DIRS | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_WITH_ALTERED_SEARCH_PATH)
#define LLEXW_ASDATAFILE	(LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_DATAFILE)
#define LLDLL_401			(LOAD_LIBRARY_SEARCH_USER_DIRS | DONT_RESOLVE_DLL_REFERENCES)

#define CNVTD_DONT_RESOLVE_DLL_REFERENCES 0x2
#define LOAD_PACKAGED_LIBRARY 0x4
#define CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET 0x800000
#define CNVTD_LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY 0x80000000

#define LoadOwner 0x1000
#define LoaderWorker 0x2000

#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD 0x40000

// OBJECT_ATTRIBUTES.Attributes
#define OBJ_INHERIT 0x00000002
#define OBJ_PERMANENT 0x00000010
#define OBJ_EXCLUSIVE 0x00000020
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_OPENIF 0x00000080
#define OBJ_OPENLINK 0x00000100
#define OBJ_KERNEL_HANDLE 0x00000200
#define OBJ_FORCE_ACCESS_CHECK 0x00000400
#define OBJ_VALID_ATTRIBUTES 0x000007f2
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP 0x800

// PEB.Bitfield
#define IsPackagedProcess 0x10

// PEB.TracingFlags
#define HeapTracingEnabled 0x1
#define CritSecTracingEnabled 0x2
#define LibLoaderTracingEnabled 0x4

// LDR_DATA_TABLE_ENTRY.Flags
#define	PackagedBinary			0x00000001
#define	MarkedForRemoval		0x00000002
#define	ImageDll				0x00000004
#define	LoadNotificationsSent	0x00000008
#define	TelemetryEntryProcessed	0x00000010
#define	ProcessStaticImport		0x00000020
#define	InLegacyLists			0x00000040
#define	InIndexes				0x00000080
#define	ShimDll					0x00000100
#define	InExceptionTable		0x00000200
#define	ReservedFlags1			0x00000C00
#define	LoadInProgress			0x00001000
#define	LoadConfigProcessed		0x00002000
#define	EntryProcessed			0x00004000
#define	ProtectDelayLoad		0x00008000
#define	ReservedFlags3			0x00030000
#define	DontCallForThreads		0x00040000
#define	ProcessAttachCalled		0x00080000
#define	ProcessAttachFailed		0x00100000
#define	CorDeferredValidate		0x00200000
#define	CorImage				0x00400000
#define	DontRelocate			0x00800000
#define	CorILOnly				0x01000000
#define	ReservedFlags5			0x0E000000
#define	Redirected				0x10000000
#define	ReservedFlags6			0x60000000
#define	CompatDatabaseProcessed	0x80000000

namespace WID
{
	namespace Loader
	{
		enum class LOADTYPE
		{
			DEFAULT = 0,
			HIDDEN
		};

		class LOADLIBRARY
		{
		private:
			NTSTATUS Load();

			// NT Functions
			NTSTATUS __fastcall LdrpThreadTokenSetMainThreadToken();
			NTSTATUS __fastcall LdrpThreadTokenUnsetMainThreadToken();

			LDR_DATA_TABLE_ENTRY* __fastcall LdrpHandleReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry);
			NTSTATUS __fastcall LdrpFreeReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry);
			NTSTATUS __fastcall LdrpResolveDllName(LDRP_LOAD_CONTEXT* LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer, PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, DWORD Flags);

			// Using directly is not recommended.
			HMODULE __fastcall fLoadLibrary(PTCHAR lpLibFileName);
			HMODULE __fastcall fLoadLibraryA(LPCSTR lpLibFileName);
			HMODULE __fastcall fLoadLibraryW(LPCWSTR lpLibFileName);
			HMODULE __fastcall fLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
			HMODULE __fastcall fLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
			
			NTSTATUS __fastcall fLdrLoadDll(PWSTR DllPath, PULONG pFlags, PUNICODE_STRING DllName, PVOID* BaseAddress);
			NTSTATUS __fastcall fLdrpLoadDll(PUNICODE_STRING DllName, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, LDR_DATA_TABLE_ENTRY** DllEntry);
			NTSTATUS __fastcall fLdrpLoadDllInternal(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus, ULONGLONG Zero);

			NTSTATUS __fastcall fLdrpProcessWork(PLDRP_LOAD_CONTEXT LoadContext, BOOLEAN IsLoadOwner);
			NTSTATUS __fastcall fLdrpSnapModule(PLDRP_LOAD_CONTEXT LoadContext);
			NTSTATUS __fastcall fLdrpMapDllRetry(PLDRP_LOAD_CONTEXT LoadContext);
			NTSTATUS __fastcall fLdrpMapDllFullPath(PLDRP_LOAD_CONTEXT LoadContext);
			NTSTATUS __fastcall fLdrpMapDllSearchPath(PLDRP_LOAD_CONTEXT LoadContext);
			NTSTATUS __fastcall fLdrpMapDllNtFileName(PLDRP_LOAD_CONTEXT LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer);
			NTSTATUS __fastcall fLdrpMapDllWithSectionHandle(PLDRP_LOAD_CONTEXT LoadContext, HANDLE SectionHandle);

			NTSTATUS __fastcall fLdrpMinimalMapModule(PLDRP_LOAD_CONTEXT LoadContext, HANDLE SectionHandle);
			NTSTATUS __fastcall fLdrpMapViewOfSection(HANDLE SectionHandle, ULONG ProtectFlags, PIMAGE_DOS_HEADER* BaseAddress, DWORD Unknown, PULONG ViewSize, ULONG AllocationType, ULONG Win32Protect, PUNICODE_STRING FullDllName);
			NTSTATUS __fastcall fLdrpCompleteMapModule(PLDRP_LOAD_CONTEXT LoadContext, PIMAGE_NT_HEADERS OutHeaders, NTSTATUS Status);
			NTSTATUS __fastcall fLdrpRelocateImage(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeaders, PUNICODE_STRING FullDllName);
			//NTSTATUS __fastcall fLdrpProtectAndRelocateImage(PIMAGE_DOS_HEADER DllBase);
			NTSTATUS __fastcall fLdrpProtectAndRelocateImage(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeader);
			NTSTATUS __fastcall	fLdrpSetProtection(PIMAGE_DOS_HEADER DllBase, BOOLEAN Unknown);
			NTSTATUS __fastcall fLdrRelocateImageWithBias(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeader);
			PIMAGE_NT_HEADERS __fastcall fLdrProcessRelocationBlockLongLong(USHORT Machine, ULONG64 Signature, ULONG64 Unknown, PIMAGE_NT_HEADERS64 NtHeader, ULONG64 Unknown3);

			NTSTATUS __fastcall fLdrpProcessMappedModule(PLDR_DATA_TABLE_ENTRY LdrEntry, ULONG64 Flags, ULONG Unknown);
			NTSTATUS __fastcall fLdrpCorProcessImports(PLDR_DATA_TABLE_ENTRY LdrEntry);
			NTSTATUS* __fastcall fLdrpMapAndSnapDependency(PLDRP_LOAD_CONTEXT LoadContext);
			NTSTATUS __fastcall fLdrpPrepareImportAddressTableForSnap(LDRP_LOAD_CONTEXT* LoadContext);


			NTSTATUS __fastcall fLdrpPrepareModuleForExecution(PLDR_DATA_TABLE_ENTRY LdrEntry, NTSTATUS* pStatus);

			NTSTATUS __fastcall fBasepLoadLibraryAsDataFileInternal(PUNICODE_STRING DllName, PWSTR Path, PWSTR Unknown, DWORD dwFlags, HMODULE* pBaseOfLoadedModule);
		public:
			LOADLIBRARY(TCHAR* DllPath, DWORD Flags = 0, LOADTYPE LoadType = LOADTYPE::DEFAULT);
			~LOADLIBRARY();

			NTSTATUS Unload();

			struct CREATIONINFO
			{
				TCHAR DllPath[MAX_PATH];
				DWORD Flags;
				LOADTYPE LoadType;
			} CreationInfo;


			HMODULE DllHandle;
			//TCHAR* FullPath;
			//TCHAR* FilePart;
		};
	}
}