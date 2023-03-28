#include "Loader.h"

using namespace WID::Loader;
LOADLIBRARY::LOADLIBRARY(TCHAR* DllPath, DWORD Flags, LOADTYPE LoadType)
{
	assert(DllPath);
	assert(GetFileAttributes(DllPath) != INVALID_FILE_ATTRIBUTES);

	if (!bInitialized)
		Init();

	memcpy(CreationInfo.DllPath, DllPath, MAX_PATH * sizeof(TCHAR));
	CreationInfo.Flags = Flags;
	CreationInfo.LoadType = LoadType;

	DllHandle = NULL;
	
	/*
	DWORD FullPathSize = 0;
	do
	{
		static DWORD BufferSize = MAX_PATH * sizeof(TCHAR);
		FullPath = new TCHAR[BufferSize];

		FullPathSize = GetFullPathName(DllPath, BufferSize, FullPath, &FilePart);
		if (!FullPathSize || !FilePart)
		{
			assert(FALSE);
		}

		if (FullPathSize <= BufferSize)
		{
			assert(GetFileAttributes(FullPath) != INVALID_FILE_ATTRIBUTES);
			break;
		}

		delete[] FullPath;
		BufferSize = FullPathSize;
	} while (FullPathSize > MAX_PATH * sizeof(TCHAR));
	*/

	NTSTATUS Status = STATUS_SUCCESS;
	if (Status = Load(), NT_SUCCESS(Status))
	{
		WID_DBG( printf("[WID] >> (Path: %s), (Flags: %lu) load successful.\n", DllPath, Flags); )
	}
	else
	{
		WID_DBG( printf("[WID] >> (Path: %s), (Flags: %lu) load failed.\n", DllPath, Flags); )
	}
}

LOADLIBRARY::~LOADLIBRARY()
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (Status = Unload(), NT_SUCCESS(Status))
	{
		WID_DBG( printf("[WID] >> (Path: %s), (Flags: %lu) unload successful.\n", CreationInfo.DllPath, CreationInfo.Flags); )
	}
	else
	{
		WID_DBG( printf("[WID] >> (Path: %s), (Flags: %lu) unload failed, err: 0x%X.\n", CreationInfo.DllPath, CreationInfo.Flags, Status); )
	}
}


NTSTATUS LOADLIBRARY::Load()
{
	if (!CreationInfo.DllPath)
		return STATUS_INVALID_PARAMETER;

	switch (CreationInfo.LoadType)
	{
	case LOADTYPE::DEFAULT:
	case LOADTYPE::HIDDEN:
		DllHandle = fLoadLibrary(CreationInfo.DllPath);
		if (!DllHandle || DllHandle == INVALID_HANDLE_VALUE)
			break;
		return STATUS_SUCCESS;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_UNSUCCESSFUL;
}



HMODULE __fastcall LOADLIBRARY::fLoadLibrary(PTCHAR lpLibFileName)
{
#ifndef _UNICODE
	return fLoadLibraryA(lpLibFileName);
#else
	return fLoadLibraryW(lpLibFileName);
#endif
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryA(LPCSTR lpLibFileName)
{
	// If no path was given.
	if (!lpLibFileName)
		//return LoadLibraryExA(lpLibFileName, 0, 0);
		return NULL;

	// If path isn't 'twain_32.dll'
	// This is where our LoadLibrary calls mostly end up.
	if (_stricmp(lpLibFileName, "twain_32.dll"))
		return fLoadLibraryExA(lpLibFileName, 0, 0);

	// If path is 'twain_32.dll'
	// Windows probably uses this to make itself a shortcut, while we are using it the code won't reach here.
	// PCHAR Heap = (PCHAR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, KernelBaseGlobalData, MAX_PATH);
	PCHAR Heap = (PCHAR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, 0, MAX_PATH);
	if (!Heap)
		return fLoadLibraryExA(lpLibFileName, 0, 0);

	HMODULE Module;
	// Heap receives the Windows path (def: C:\Windows)

	// The BufferSize check made against GetWindowsDirectoryA is to see if it actually received. If it's bigger than BufferSize 
	// then GetWindowsDirectoryA returned the size needed (in summary it fails)

	// If this check doesn't fail '\twain_32.dll' is appended to the Windows path (def: C:\Windows\twain_32.dll)
	// Then this final module is loaded into the program.
	// If it can't load, it tries to load it directly and returns from there.
	if (GetWindowsDirectoryA(Heap, MAX_PATH) - 1 > 0xF5 ||
		(strncat_s(Heap, MAX_PATH, "\\twain_32.dll", strlen("\\twain_32.dll")), (Module = fLoadLibraryA(Heap)) == 0))
	{
		RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
		return fLoadLibraryExA(lpLibFileName, 0, 0);
	}
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
	return Module;
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryW(LPCWSTR lpLibFileName)
{
	return fLoadLibraryExW(lpLibFileName, 0, 0);
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{	
	UNICODE_STRING Unicode;
	if (!Basep8BitStringToDynamicUnicodeString(&Unicode, lpLibFileName))
		return NULL;

	HMODULE Module = fLoadLibraryExW(Unicode.Buffer, hFile, dwFlags);
	RtlFreeUnicodeString(&Unicode);
	return Module;
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	NTSTATUS Status;

	DWORD ConvertedFlags;
	HMODULE BaseOfLoadedDll;

	DWORD DatafileFlags = dwFlags & LLEXW_ASDATAFILE;
	// If no DllName was given OR hFile was given (msdn states that hFile must be 0) OR dwFlags is set to an unknown value OR *both* the Datafile flags are set (they cannot be used together).
	if (!lpLibFileName || hFile || ((dwFlags & 0xFFFF0000) != 0) || (DatafileFlags == LLEXW_ASDATAFILE))
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	UNICODE_STRING DllName;
	Status = RtlInitUnicodeStringEx(&DllName, lpLibFileName);
	if (NT_SUCCESS(Status) == FALSE)
	{
		BaseSetLastNTError(Status);
		return NULL;
	}

	USHORT DllNameLen = DllName.Length;
	if (!DllName.Length)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
		return NULL;
	}

	// If the DllName given had empty (space) chars as their last chars, this do-while loop excludes them and sets the excluded length.
	do
	{
		DWORD WchAmount = DllNameLen / 2;
		if (DllName.Buffer[WchAmount - 1] != ' ' /* 0x20 is space char */)
			break;

		DllNameLen -= 2;
		DllName.Length = DllNameLen;
	} while (DllNameLen != 2);

	// In case the above do-while loop misbehaves.
	if (DllNameLen == 0)
	{
		BaseSetLastNTError(STATUS_INVALID_PARAMETER);
			return NULL;
	}

	BaseOfLoadedDll = 0;

	// If the dll is not getting loaded as a datafile.
	if ((dwFlags & LLEXW_ISDATAFILE) == 0)
	{
		// Converts the actual flags into it's own flag format. Most flags are discarded (only used if loaded as datafile).
		// Only flags that can go through are DONT_RESOLVE_DLL_REFERENCES, LOAD_PACKAGED_LIBRARY, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET and LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY
		ConvertedFlags = 0;
		if ((dwFlags & DONT_RESOLVE_DLL_REFERENCES) != 0)
			ConvertedFlags |= CNVTD_DONT_RESOLVE_DLL_REFERENCES;

		if ((dwFlags & LOAD_PACKAGED_LIBRARY) != 0)
			ConvertedFlags |= LOAD_PACKAGED_LIBRARY;

		if ((dwFlags & LOAD_LIBRARY_REQUIRE_SIGNED_TARGET) != 0)
			ConvertedFlags |= CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET;

		if ((dwFlags & LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY) != 0)
			ConvertedFlags |= CNVTD_LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY;

		// Evaluates dwFlags to get meaningful flags, includes DONT_RESOLVE_DLL_REFERENCES finally.
		// But it doesn't matter because the first param LdrLoadDll takes actually a (PWCHAR PathToFile), so I have no idea why that's done.
		Status = fLdrLoadDll((PWCHAR)((dwFlags & LLEXW_7F08) | 1), &ConvertedFlags, &DllName, (PVOID*)&BaseOfLoadedDll);
		if (NT_SUCCESS(Status))
			return BaseOfLoadedDll;

		BaseSetLastNTError(Status);
		return NULL;
	}

	PWSTR Path;
	PWSTR Unknown;
	// Gets the Dll path.
	Status = LdrGetDllPath(DllName.Buffer, (dwFlags & LLEXW_7F08), &Path, &Unknown);
	if (NT_SUCCESS(Status) == FALSE)
	{
		BaseSetLastNTError(Status);
		return NULL;
	}

	// First step into loading a module as datafile.
	Status = fBasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, dwFlags, &BaseOfLoadedDll);
	// If the Status is only success (excludes warnings) AND if the module is image resource, loads again. I don't know why.
	if (NT_SUCCESS(Status + 0x80000000) && Status != STATUS_NO_SUCH_FILE && (dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE) != 0)
	{
		if (DatafileFlags)
			Status = fBasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, DatafileFlags, &BaseOfLoadedDll);
	}

	RtlReleasePath(Path);
	BaseSetLastNTError(Status);
	return NULL;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrLoadDll(PWSTR DllPath, PULONG pFlags, PUNICODE_STRING DllName, PVOID* BaseAddress)
{
	NTSTATUS Status;

	// DllPath can also be used as Flags if called from LoadLibraryExW

	ULONG FlagUsed = 0;
	if (pFlags)
	{
		// Only flags that could go through *LoadLibraryExW* were;
		// CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2)
		// LOAD_PACKAGED_LIBRARY (0x4)
		// CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x800000)
		// CNVTD_LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY (0x80000000)
		// So I am assuming the rest of the flags are 0.

		ULONG ActualFlags = *pFlags;
		// If LOAD_PACKAGED_LIBRARY (0x4) flag is set (1) FlagUsed becomes CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2), if not set (0) FlagUsed becomes 0.
		FlagUsed = CNVTD_DONT_RESOLVE_DLL_REFERENCES * (ActualFlags & LOAD_PACKAGED_LIBRARY);

		// (MSDN about DONT_RESOLVE_DLL_REFERENCES) Note  Do not use this value; it is provided only for backward compatibility.
		// If you are planning to access only data or resources in the DLL, use LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
		// or LOAD_LIBRARY_AS_IMAGE_RESOURCE or both. Otherwise, load the library as a DLL or executable module using the LoadLibrary function.
		FlagUsed |= ((ActualFlags & CNVTD_DONT_RESOLVE_DLL_REFERENCES)			? LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE : NULL);
		FlagUsed |= ((ActualFlags & CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET)	? LOAD_LIBRARY_REQUIRE_SIGNED_TARGET : NULL);

		// Ignored because ActualFlags can't have 0x1000 (if called from LoadLibraryExW), this value is used probably in calls from different functions.
		FlagUsed |= ((ActualFlags & 0x1000) ? 0x100 : 0x0);
		// Ignored because ActualFlags can't be negative (if called from LoadLibraryExW), this value is used probably in calls from different functions.
		FlagUsed |= ((ActualFlags < 0) ? 0x400000 : 0x0);

		// To sum up, in case we are called from LoadLibraryExW, the most flags we can have are;
		// CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80)
	}

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x244, "LdrLoadDll", 3u, "DLL name: %wZ\n", DllName); )

	if ((*LdrpPolicyBits & 4) == 0 && ((UINT16)DllPath & LLDLL_401) == LLDLL_401)
		return STATUS_INVALID_PARAMETER;

	// In here it will go in by the first condition, because 8 couldn't be set by LoadLibraryExW.
	if ((FlagUsed & LOAD_WITH_ALTERED_SEARCH_PATH) == 0 || (*LdrpPolicyBits & 8) != 0)
	{
		// If the current thread is a Worker Thread it fails.
		if (NtCurrentTeb()->SameTebFlags & LoaderWorker)
		{
			Status = STATUS_INVALID_THREAD;
		}
		else
		{
			LDR_UNKSTRUCT DllPathInited;
			// There's another LdrpLogInternal inside this function, gonna mess with that later on.
			LdrpInitializeDllPath(DllName->Buffer, DllPath, &DllPathInited);

			LDR_DATA_TABLE_ENTRY* DllEntry;
			Status = fLdrpLoadDll(DllName, &DllPathInited, FlagUsed, &DllEntry);
			if (DllPathInited.IsInitedMaybe)
				RtlReleasePath(DllPathInited.pInitNameMaybe);
			if (NT_SUCCESS(Status))
			{
				// Changes the actual return value and dereferences the module.
				*BaseAddress = DllEntry->DllBase;
				LdrpDereferenceModule(DllEntry);
			}
		}
	}
	else
	{
		WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x259, "LdrLoadDll", 0, "Nonpackaged process attempted to load a packaged DLL.\n"); )
		Status = STATUS_NO_APPLICATION_PACKAGE;
	}
	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x279, "LdrLoadDll", 4, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDll(PUNICODE_STRING DllName, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, LDR_DATA_TABLE_ENTRY** DllEntry)
{
	NTSTATUS Status;

	WID_HIDDEN( LdrpLogDllState(0, DllName, 0x14A8); )

	// Flags is passed by value so no need to create a backup, it's already a backup by itself.
	// MOST FLAGS = CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80)

	// Creates a new unicode_string and allocates it some buffer.
	UNICODE_STRING FullDllPath;
	//WCHAR Buffer[128];
	// Sets the according members.
	//FullDllPath.Length = 0x1000000;
	//FullDllPath.Buffer = Buffer;
	//Buffer[0] = 0;

	// Might not be what's done actually. Works though.
	WCHAR Buffer[MAX_PATH];
	wcscpy(Buffer, DllName->Buffer);

	FullDllPath.Length = wcslen(DllName->Buffer) * 2;
	FullDllPath.MaximumLength = MAX_PATH - 4;
	FullDllPath.Buffer = Buffer;
	 
	// Returns the Absolute path
	// If a non-relative path was given then the flags will be ORed with LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) | LOAD_LIBRARY_SEARCH_USER_DIRS (0x400)
	// resulting in the MOST FLAGS being:
	// CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80) |
	// LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) | LOAD_LIBRARY_SEARCH_USER_DIRS (0x400)
	ULONG Zero = 0;
	Status = LdrpPreprocessDllName(DllName, &FullDllPath, &Zero, &Flags);

	if (NT_SUCCESS(Status))
		// A even deeper function, by far we can see Windows is kinda all *wrapped* around each other.
		fLdrpLoadDllInternal(&FullDllPath, DllPathInited, Flags, ImageDll, 0, 0, DllEntry, &Status, 0);

	if (Buffer != FullDllPath.Buffer)
		NtdllpFreeStringRoutine(FullDllPath.Buffer);

	// I don't see no point in this but anyways.
	FullDllPath.Length = 0x1000000;
	FullDllPath.Buffer = Buffer;
	Buffer[0] = 0;
	WID_HIDDEN( LdrpLogDllState(0, DllName, 0x14A9); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDllInternal(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus, ULONGLONG Zero)
{
	NTSTATUS Status;

	// NOTES:
	// I assumed that LdrFlags (which was sent as 0x4 (ImageDll) by LdrpLoadDll) is the same flags inside LDR_DATA_TABLE_ENTRY.
	// LdrEntry & LdrEntry2 were both sent as 0s by LdrpLoadDll.
	// 
	// Instead of using gotos which causes the local variables to be initialized in the start of the function (making it look not good in my opinion)
	// I created a do-while loop. The outcome won't be affected.
	//
	// MOST FLAGS = CONVERTED_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80)
	// LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) | LOAD_LIBRARY_SEARCH_USER_DIRS (0x400)

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x379, "LdrpLoadDllInternal", 3, "DLL name: %wZ\n", FullPath); )
	do
	{
		*DllEntry = 0;

		// This will go in.
		if (LdrFlags != (PackagedBinary | LoadNotificationsSent))
		{
			// This function does some prior setup, incrementing the module load count is done inside here.
			Status = LdrpFastpthReloadedDll(FullPath, Flags, LdrEntry2, DllEntry);

			// If not an actual nt success (excludes warnings)
			if ((NT_SUCCESS((Status + 0x80000000)) == FALSE) || Status == STATUS_IMAGE_LOADED_AS_PATCH_IMAGE)
			{
				*pStatus = Status;
				break;
			}
		}

		bool IsWorkerThread = ((NtCurrentTeb()->SameTebFlags & LoadOwner) == 0);
		if (IsWorkerThread)
			LdrpDrainWorkQueue(WaitLoadComplete);

		// This won't go in so we can ignore it. I still did simplifying though.
		// Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one.
		if (LdrFlags == (PackagedBinary | LoadNotificationsSent))
		{
			Status = LdrpFindLoadedDllByHandle(Zero, &LdrEntry, 0);
			if (!NT_SUCCESS(Status))
			{
				// FREE_DLLNAMEPREPROCANDRETURN;
				if (FullPath->Buffer)
					LdrpFreeUnicodeString(FullPath);

				*pStatus = Status;
				if (IsWorkerThread)
					LdrpDropLastInProgressCount();
				break;
			}

			if (LdrEntry->HotPatchState == LdrHotPatchFailedToPatch)
			{
				Status = STATUS_PATCH_CONFLICT;

				// goto FREE_DLLNAMEPREPROCANDRETURN;
				if (FullPath->Buffer)
					LdrpFreeUnicodeString(FullPath);

				*pStatus = Status;
				if (IsWorkerThread)
					LdrpDropLastInProgressCount();
				break;
			}

			Status = LdrpQueryCurrentPatch(LdrEntry->CheckSum, LdrEntry->TimeDateStamp, FullPath);
			if (!NT_SUCCESS(Status))
			{
				// goto FREE_DLLNAMEPREPROCANDRETURN;
				if (FullPath->Buffer)
					LdrpFreeUnicodeString(FullPath);

				*pStatus = Status;
				if (IsWorkerThread)
					LdrpDropLastInProgressCount();
				break;
			}

			if (!FullPath->Length)
			{
				if (LdrEntry->ActivePatchImageBase)
					Status = LdrpUndoPatchImage(LdrEntry);

				// goto FREE_DLLNAMEPREPROCANDRETURN;
				if (FullPath->Buffer)
					LdrpFreeUnicodeString(FullPath);

				*pStatus = Status;
				if (IsWorkerThread)
					LdrpDropLastInProgressCount();
				break;
			}

			LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x3FA, "LdrpLoadDllInternal", 2, "Loading patch image: %wZ\n", FullPath);

		}

		// Opens a token to the current thread and sets GLOBAL variable LdrpMainThreadToken with that token.
		LdrpThreadTokenSetMainThreadToken();

		LDR_DATA_TABLE_ENTRY* pLdrEntryLoaded = 0;
		// This will go in by the first check LdrEntry2 because it was sent as 0 in LdrpLoadDll.
		if (!LdrEntry2 || !IsWorkerThread || LdrEntry2->DdagNode->LoadCount)
		{
			// I checked the function, it detects a hook by byte scanning these following functions;
			// • ntdll!NtOpenFile
			// • ntdll!NtCreateSection
			// • ntdll!ZqQueryAttributes
			// • ntdll!NtOpenSection
			// • ntdll!ZwMapViewOfSection
			// Resulting in the global variable LdrpDetourExist to be set if there's a hook, didn't checked what's done with it though.
			LdrpDetectDetour();

			// [IGNORE THIS] Finds the module, increments the loaded module count. [IGNORE THIS]
			// [IGNORE THIS] It can go to another direction if the Flag LOAD_LIBRARY_SEARCH_APPLICATION_DIR was set, but that couldn't be set coming from LoadLibraryExW. [IGNORE THIS]
			// If LoadLibrary was given an absolute path, Flags will have LOAD_LIBRARY_SEARCH_APPLICATION_DIR causing this function to call LdrpLoadKnownDll.
			// In our case LdrpFindOrPrepareLoadingModule actually returns STATUS_DLL_NOT_FOUND, which I thought was a bad thing but after checking up inside
			// inside LdrpProcessWork it didn't looked that bad.
			// So our dll loading part is actually inside LdrpProcessWork (for calling LoadLibraryExW with an absolute path and 0 flags at least)
			Status = LdrpFindOrPrepareLoadingModule(FullPath, DllPathInited, Flags, LdrFlags, LdrEntry, &pLdrEntryLoaded, pStatus);
			if (Status == STATUS_DLL_NOT_FOUND)
				fLdrpProcessWork(pLdrEntryLoaded->LoadContext, TRUE);
			else if (Status != STATUS_RETRY && NT_SUCCESS(Status) == FALSE)
				*pStatus = Status;
		}
		else
		{
			*pStatus = STATUS_DLL_NOT_FOUND;
		}

		LdrpDrainWorkQueue(WaitWorkComplete);

		if (LdrpMainThreadToken)
			// Closes the token handle, and sets GLOBAL variable LdrpMainThreadToken to 0.
			LdrpThreadTokenUnsetMainThreadToken();
		if (pLdrEntryLoaded)
		{
			*DllEntry = LdrpHandleReplacedModule(pLdrEntryLoaded);
			if (pLdrEntryLoaded != *DllEntry)
			{
				LdrpFreeReplacedModule(pLdrEntryLoaded);
				pLdrEntryLoaded = *DllEntry;
				if (pLdrEntryLoaded->LoadReason == LoadReasonPatchImage && LdrFlags != (PackagedBinary | LoadNotificationsSent))
					*pStatus = STATUS_IMAGE_LOADED_AS_PATCH_IMAGE;
			}
			if (pLdrEntryLoaded->LoadContext)
				LdrpCondenseGraph(pLdrEntryLoaded->DdagNode);
			if (NT_SUCCESS(*pStatus))
			{
				// [IGNORE THIS] In here I realized that the module must have already been loaded to be prepared for execution.
				// [IGNORE THIS] So I've gone a little back and realized the actual loading was done in the LdrpDrainWorkQueue function.
				// Doing more research revealed it was inside LdrpProcessWork after LdrpFindOrPrepareLoadingModule returning STATUS_DLL_NOT_FOUND.

				// This function is pretty interesting, had a quick look and seen a lot. Gonna reverse this one too.
				Status = fLdrpPrepareModuleForExecution(pLdrEntryLoaded, pStatus);
				*pStatus = Status;
				if (NT_SUCCESS(Status))
				{
					Status = LdrpBuildForwarderLink(LdrEntry2, pLdrEntryLoaded);
					*pStatus = Status;
					if (NT_SUCCESS(Status) && !*LdrInitState)
						LdrpPinModule(pLdrEntryLoaded);
				}

				// Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one too.
				if (LdrFlags == (PackagedBinary | LoadNotificationsSent) && LdrEntry->ActivePatchImageBase != pLdrEntryLoaded->DllBase)
				{
					if (pLdrEntryLoaded->HotPatchState == LdrHotPatchFailedToPatch)
					{
						*pStatus = STATUS_DLL_INIT_FAILED;
					}
					else
					{
						Status = LdrpApplyPatchImage(pLdrEntryLoaded);
						*pStatus = Status;
						if (NT_SUCCESS(Status) == FALSE)
						{
							//UNICODE_STRING Names[4];
							//Names[0] = pLdrEntryLoaded->FullDllName;
							//WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x4AF, "LdrpLoadDllInternal", 0, "Applying patch \"%wZ\" failed\n", Names); )
							WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x4AF, "LdrpLoadDllInternal", 0, "Applying patch \"%wZ\" failed\n", pLdrEntryLoaded->FullDllName.Buffer); )
						}
					}
				}
			}
			LdrpFreeLoadContextOfNode(pLdrEntryLoaded->DdagNode, pStatus);
			if (!NT_SUCCESS(*pStatus) && (LdrFlags != (PackagedBinary | LoadNotificationsSent) || pLdrEntryLoaded->HotPatchState != LdrHotPatchAppliedReverse))
			{
				*DllEntry = 0;
				LdrpDecrementModuleLoadCountEx(pLdrEntryLoaded, 0);
				LdrpDereferenceModule(pLdrEntryLoaded);
			}
		}
		else
		{
			*pStatus = STATUS_NO_MEMORY;
		}
	} while (FALSE);

	// LoadNotificationsSent (0x8) | PackagedBinary (0x1)
	// Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one too.
	if (LdrFlags == (LoadNotificationsSent | PackagedBinary) && LdrEntry)
		LdrpDereferenceModule(LdrEntry);

	Status = STATUS_SUCCESS;
	WID_HIDDEN( { Status = LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x52E, "LdrpLoadDllInternal", 4, "Status: 0x%08lx\n", *pStatus); } )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpProcessWork(PLDRP_LOAD_CONTEXT LoadContext, BOOLEAN IsLoadOwner)
{
	NTSTATUS Status;

	// Converted goto to do-while loop.
	do
	{
		Status = *LoadContext->pStatus;
		if (!NT_SUCCESS(Status))
			break;

		// Caused most likely because CONTAINING_RECORD macro was used, I have no idea what's going on.
		// Also the structure used (LDRP_LOAD_CONTEXT) isn't documented, that's what I've got out of it so far.
		if ((UINT_PTR)LoadContext->WorkQueueListEntry.Flink[9].Blink[3].Blink && MAXDWORD)
		{
			Status = fLdrpSnapModule(LoadContext);
		}
		else
		{
			if ((LoadContext->Flags & 0x100000) != 0)
			{
				Status = fLdrpMapDllRetry(LoadContext);
			}
			// We will continue from here since we have the LOAD_LIBRARY_SEARCH_APPLICATION_DIR flag, and also the function name is exactly representing
			// what we are expecting to happen.
			else if ((LoadContext->Flags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR) != 0)
			{
				Status = fLdrpMapDllFullPath(LoadContext);
			}
			else
			{
				Status = fLdrpMapDllSearchPath(LoadContext);
			}
			if (NT_SUCCESS(Status) || Status == STATUS_RETRY)
				break;

			//Status = LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x7D2, "LdrpProcessWork", 0, "Unable to load DLL: \"%wZ\", Parent Module: \"%wZ\", Status: 0x%x\n", LoadContext, &LoadContext->Entry->FullDllName & (unsigned __int64)((unsigned __int128)-(__int128)(unsigned __int64)LoadContext->Entry >> 64), Status);
			WID_HIDDEN( Status = LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x7D2, "LdrpProcessWork", 0, "Unable to load DLL: \"%wZ\", Parent Module: \"%wZ\", Status: 0x%x\n", LoadContext, ((UINT_PTR)&LoadContext->Entry->FullDllName & (UINT_PTR)LoadContext->Entry >> 64), Status); )
			// This part is for failed cases so we can ignore it.
			if (Status == STATUS_DLL_NOT_FOUND)
			{
				WID_HIDDEN( LdrpLogError(STATUS_DLL_NOT_FOUND, 0x19, 0, LoadContext); )
				WID_HIDDEN( LdrpLogDeprecatedDllEtwEvent(LoadContext); )
				//LdrpLogLoadFailureEtwEvent((DWORD)LoadContext,(DWORD(LoadContext->Entry) + 0x48) & ((unsigned __int128)-(__int128)(unsigned __int64)LoadContext->Entry >> 64),STATUS_DLL_NOT_FOUND,(unsigned int)&LoadFailure,0);
				WID_HIDDEN( LdrpLogLoadFailureEtwEvent((PVOID)LoadContext, (PVOID)(((UINT_PTR)(LoadContext->Entry->EntryPointActivationContext) & ((UINT_PTR)(LoadContext->Entry) >> 64))), STATUS_DLL_NOT_FOUND, LoadFailure, 0); )

				PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)LoadContext->WorkQueueListEntry.Flink;
				if ((pLdrEntry->FlagGroup[0] & ProcessStaticImport) != 0)
				{
					WID_HIDDEN( Status = LdrpReportError(LoadContext, 0, STATUS_DLL_NOT_FOUND); )
				}
			}
		}
		if (!NT_SUCCESS(Status))
		{
			*LoadContext->pStatus = Status;
		}
	} while (FALSE);

	if (!IsLoadOwner)
	{
		bool SetWorkCompleteEvent;

		//RtlEnterCriticalSection(&LdrpWorkQueueLock);
		RtlEnterCriticalSection(LdrpWorkQueueLock);
		--(*LdrpWorkInProgress);
		if (*LdrpWorkQueue != (LIST_ENTRY*)LdrpWorkQueue || (SetWorkCompleteEvent = 1, *LdrpWorkInProgress != 1))
			SetWorkCompleteEvent = FALSE;
		//Status = RtlLeaveCriticalSection(&LdrpWorkQueueLock);
		Status = RtlLeaveCriticalSection(LdrpWorkQueueLock);
		if (SetWorkCompleteEvent)
			Status = ZwSetEvent(*LdrpWorkCompleteEvent, 0);
	}

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpSnapModule(PLDRP_LOAD_CONTEXT LoadContext)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllRetry(PLDRP_LOAD_CONTEXT LoadContext)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllFullPath(PLDRP_LOAD_CONTEXT LoadContext)
{
	NTSTATUS Status;
	
	LDR_DATA_TABLE_ENTRY* LdrEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	

	/*
	WCHAR Buffer[128];
	FileNameBuffer.Length = 0x1000000;
	FileNameBuffer.MaximumLength = 0x1000000;
	FileNameBuffer.Buffer = Buffer;
	Buffer[0] = 0;
	*/

	// Might not be what's done actually. Works though.
	LDRP_FILENAME_BUFFER FileNameBuffer;	

	FileNameBuffer.pFileName.Buffer = FileNameBuffer.FileName;
	FileNameBuffer.pFileName.Length = wcslen(FileNameBuffer.FileName);
	FileNameBuffer.pFileName.MaximumLength = MAX_PATH - 4;
	//FileNameBuffer.FileName[0] = 0;

	Status = LdrpResolveDllName(LoadContext, &FileNameBuffer, &LdrEntry->BaseDllName, &LdrEntry->FullDllName, LoadContext->Flags);
	do
	{
		if (LoadContext->UnknownPtr)
		{
			if (!NT_SUCCESS(Status))
				break;
		}
		else
		{
			Status = LdrpAppCompatRedirect(LoadContext, &LdrEntry->FullDllName, &LdrEntry->BaseDllName, &FileNameBuffer, Status);
			if (!NT_SUCCESS(Status))
				break;

			// Hashes the dll name
			DWORD BaseDllNameHash = LdrpHashUnicodeString(&LdrEntry->BaseDllName);
			LdrEntry->BaseNameHashValue = BaseDllNameHash;

			LDR_DATA_TABLE_ENTRY* LoadedDll = nullptr;
			LdrpFindExistingModule(&LdrEntry->BaseDllName, &LdrEntry->FullDllName, LoadContext->Flags, BaseDllNameHash, &LoadedDll);
			if (LoadedDll)
			{
				LdrpLoadContextReplaceModule(LoadContext, LoadedDll);
				break;
			}
		}

		Status = fLdrpMapDllNtFileName(LoadContext, &FileNameBuffer);
		if (Status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
			Status = STATUS_INVALID_IMAGE_FORMAT;
	} while (FALSE);

	if (FileNameBuffer.FileName != FileNameBuffer.pFileName.Buffer)
		NtdllpFreeStringRoutine(FileNameBuffer.pFileName.Buffer);

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllSearchPath(PLDRP_LOAD_CONTEXT LoadContext)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllNtFileName(PLDRP_LOAD_CONTEXT LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer)
{
	NTSTATUS Status;

	LDR_DATA_TABLE_ENTRY* LdrEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	INT64 UnknownPtr = LoadContext->UnknownPtr;
	if (LdrpCheckForRetryLoading(LoadContext, 0))
		return STATUS_RETRY;

	PUNICODE_STRING FullDllName = &LdrEntry->FullDllName;
	WID_HIDDEN( LdrpLogDllState((ULONGLONG)LdrEntry->DllBase, (PUNICODE_STRING)&LdrEntry->FullDllName, 0x14A5); )
	//OBJ_CASE_INSENSITIVE 
	ULONG ObjAttributes = OBJ_CASE_INSENSITIVE;
	if (!*LdrpUseImpersonatedDeviceMap)
		ObjAttributes = (OBJ_IGNORE_IMPERSONATED_DEVICEMAP | OBJ_CASE_INSENSITIVE);

	OBJECT_ATTRIBUTES ObjectAttributes;
	ObjectAttributes.Length = 0x30;
	ObjectAttributes.RootDirectory = 0;
	ObjectAttributes.Attributes = ObjAttributes;
	ObjectAttributes.ObjectName = &FileNameBuffer->pFileName;
	ObjectAttributes.SecurityDescriptor = 0;
	ObjectAttributes.SecurityQualityOfService = 0;

	PCHAR NtPathStuff = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2];
	INT64 Unknown2 = 0;
	if (RtlGetCurrentServiceSessionId())
		Unknown2 = (INT64)&NtCurrentPeb()->SharedData->NtSystemRoot[253];
	else
		Unknown2 = (INT64)&kUserSharedData->UserModeGlobalLogger[2];

	PCHAR NtPathStuff2 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
	if (*(BYTE*)Unknown2 && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
	{
		//: (char*)0x7FFE0385;
		PCHAR NtPathStuff3 = RtlGetCurrentServiceSessionId() ? (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1 : (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
			
		// 0x20 is SPACE char
		if ((*NtPathStuff3 & ' ') != 0)
			LdrpLogEtwEvent(0x1485, -1, 0xFFu, 0xFFu);
	}

	// SYSTEM_FLAGS_INFORMATION
	if ((NtCurrentPeb()->NtGlobalFlag & FLG_ENABLE_KDEBUG_SYMBOL_LOAD) != 0)
	{
		ZwSystemDebugControl();
	}

	HANDLE FileHandle;
	while (TRUE)
	{	
		IO_STATUS_BLOCK IoStatusBlock;	
		Status = NtOpenFile(&FileHandle, SYNCHRONIZE | FILE_TRAVERSE | FILE_LIST_DIRECTORY, &ObjectAttributes, &IoStatusBlock, 5, 0x60);
		if (NT_SUCCESS(Status))
			break;

		if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
			return STATUS_DLL_NOT_FOUND;
		if (Status != STATUS_ACCESS_DENIED || !LdrpCheckComponentOnDemandEtwEvent(&LoadContext->BaseDllName))
			return Status;
	}

	ULONG SigningLevel;
	ULONG AllocationAttributes = 0;
	if (*LdrpAuditIntegrityContinuity && (Status = LdrpValidateIntegrityContinuity(LoadContext, FileHandle), !NT_SUCCESS(Status)) && *LdrpEnforceIntegrityContinuity || 
	   (AllocationAttributes = MEM_IMAGE, (LoadContext->Flags & MEM_IMAGE) != 0) && (NtCurrentPeb()->BitField & IsPackagedProcess) == 0 &&
	   (Status = LdrpSetModuleSigningLevel(FileHandle, (PLDR_DATA_TABLE_ENTRY)LoadContext->WorkQueueListEntry.Flink, &SigningLevel, 8), !NT_SUCCESS(Status)))
	{
		NtClose(FileHandle);
		return Status;
	}

	if (*UseWOW64 && (LoadContext->Flags & 0x800) == 0)
		AllocationAttributes = MEM_IMAGE | MEM_TOP_DOWN;

	HANDLE SectionHandle;
	Status = NtCreateSection(&SectionHandle, SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE, 0, 0, PAGE_EXECUTE, AllocationAttributes, FileHandle);
	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_NEEDS_REMEDIATION || (Status + 0x3FFFFB82) <= 1)
		{
			Status = LdrAppxHandleIntegrityFailure(Status);
		}
		else if (Status != STATUS_NO_MEMORY && Status != STATUS_INSUFFICIENT_RESOURCES && Status != STATUS_COMMITMENT_LIMIT)
		{
			LDR_UNKSTRUCT2 NtHardParameters;
			NtHardParameters.Name = FullDllName;
			NtHardParameters.Status = Status;
			// Semi-documented in http://undocumented.ntinternals.net/
			HARDERROR_RESPONSE Response;
			if (NT_SUCCESS(NtRaiseHardError(STATUS_INVALID_IMAGE_FORMAT, 2, 1, (INT*)&NtHardParameters, OptionOk, &Response)) && *LdrInitState != 3)
			{
				++(*LdrpFatalHardErrorCount);
			}
		}
		WID_HIDDEN( LdrpLogError(Status, 0x1485u, 0, FullDllName); )
		NtClose(FileHandle);
		return Status;
	}
	if (RtlGetCurrentServiceSessionId())
		NtPathStuff = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253];
	if (*NtPathStuff && (NtCurrentPeb()->TracingFlags & 4) != 0)
	{
		if (RtlGetCurrentServiceSessionId())
			NtPathStuff2 = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1;
		// 0x20 is SPACE char.
		if ((*NtPathStuff2 & ' ') != 0)
			WID_HIDDEN( LdrpLogEtwEvent(0x1486, -1, 0xFFu, 0xFFu); )
	}
	if (!UseWOW64 && (LoadContext->Flags & 0x100) == 0 && (Status = LdrpCodeAuthzCheckDllAllowed(&FileNameBuffer->pFileName, FileHandle), NT_SUCCESS(Status + 0x80000000))
		&& Status != STATUS_NOT_FOUND || (Status = fLdrpMapDllWithSectionHandle(LoadContext, SectionHandle), !UnknownPtr) || !NT_SUCCESS(Status))
	{
		NtClose(SectionHandle);
		NtClose(FileHandle);
		return Status;
	}
	LoadContext->FileHandle = FileHandle;
	LoadContext->SectionHandle = SectionHandle;
	return Status;
}


NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllWithSectionHandle(PLDRP_LOAD_CONTEXT LoadContext, HANDLE SectionHandle)
{
	NTSTATUS Status;
		
	int v19[14];
	
	LDR_DATA_TABLE_ENTRY* LdrEntry3;
	LDR_DATA_TABLE_ENTRY* LdrEntry4;

	Status = LdrpMinimalMapModule(LoadContext, SectionHandle);
	if (Status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
		return Status;

	if (!NT_SUCCESS(Status))
		return Status;

	LDR_DATA_TABLE_ENTRY* LdrEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	ULONG64 Size = LoadContext->Size;
	PIMAGE_NT_HEADERS OutHeaders;
	Status = RtlImageNtHeaderEx(0, LdrEntry->DllBase, Size, &OutHeaders);
	if (!NT_SUCCESS(Status))
		return Status;

	LDR_DATA_TABLE_ENTRY* LdrEntry2 = 0;
	if ((LoadContext->Flags & SEC_FILE) != 0)
	{
		Status = STATUS_SUCCESS;
		LdrEntry->TimeDateStamp = OutHeaders->FileHeader.TimeDateStamp;
		LdrEntry->CheckSum = OutHeaders->OptionalHeader.CheckSum;
		LdrEntry->SizeOfImage = OutHeaders->OptionalHeader.SizeOfImage;
	}
	else
	{
		RtlAcquireSRWLockExclusive(LdrpModuleDatatableLock);
		ULONG64 Flags = (LoadContext->Flags);
		PUNICODE_STRING FullDllName_2 = 0;
		if ((Flags & 0x20) == 0)
			FullDllName_2 = &LdrEntry->FullDllName;
		Status = LdrpFindLoadedDllByNameLockHeld(&LdrEntry->BaseDllName, FullDllName_2, Flags, &LdrEntry2, LdrEntry->BaseNameHashValue);
		if (Status == STATUS_DLL_NOT_FOUND)
		{
			PIMAGE_DOS_HEADER DllBase = LdrEntry->DllBase;
			v19[0] = OutHeaders->FileHeader.TimeDateStamp;
			v19[1] = OutHeaders->OptionalHeader.SizeOfImage;
			LdrpFindLoadedDllByMappingLockHeld(DllBase, OutHeaders, (unsigned int*)v19, &LdrEntry2);
		}

		if (!LdrEntry2)
		{
			LdrpInsertDataTableEntry(LdrEntry);
			LdrpInsertModuleToIndexLockHeld(LdrEntry, OutHeaders);
		}

		RtlReleaseSRWLockExclusive(LdrpModuleDatatableLock);
		if (LdrEntry2)
		{
			LdrEntry3 = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
			if (LdrEntry3->LoadReason != LoadReasonPatchImage || LdrEntry2->LoadReason == LoadReasonPatchImage)
			{
				LdrpLoadContextReplaceModule(LoadContext, LdrEntry2);
			}
			else
			{
				Status = STATUS_IMAGE_LOADED_AS_PATCH_IMAGE;
				LdrpLogEtwHotPatchStatus(&(*LdrpImageEntry)->BaseDllName, LoadContext->Entry, &LdrEntry3->FullDllName, STATUS_IMAGE_LOADED_AS_PATCH_IMAGE, 3);
				LdrpDereferenceModule(LdrEntry2);
			}
			return Status;
		}
	}
	if (*qword_17E238 == NtCurrentTeb()->ClientId.UniqueThread)
		return STATUS_NOT_FOUND;
	Status = fLdrpCompleteMapModule(LoadContext, OutHeaders, Status);
	if (NT_SUCCESS(Status))
	{
		Status = fLdrpProcessMappedModule(LdrEntry, LoadContext->Flags, 1);
		if (NT_SUCCESS(Status))
		{
			WID_HIDDEN( LdrpLogNewDllLoad(LoadContext->Entry, LdrEntry); )
			LdrEntry4 = LoadContext->Entry;
			if (LdrEntry4)
				LdrEntry->ParentDllBase = LdrEntry4->DllBase;
			BOOLEAN DllBasesEqual = FALSE;
			if (LdrEntry->LoadReason == LoadReasonPatchImage && *LdrpImageEntry)
				DllBasesEqual = LdrEntry->ParentDllBase == (*LdrpImageEntry)->DllBase;
			if ((LoadContext->Flags & MEM_IMAGE) || (LdrEntry->FlagGroup[0] & ImageDll) || DllBasesEqual)
			{
				if ((LdrEntry->Flags & CorILOnly))
				{
					return fLdrpCorProcessImports(LdrEntry);
				}
				else
				{
					fLdrpMapAndSnapDependency(LoadContext);
					return *LoadContext->pStatus;
				}
			}
			else
			{
				LdrpLogDllState((ULONG)LdrEntry->DllBase, &LdrEntry->FullDllName, 0x14AEu);
				Status = STATUS_SUCCESS;
				LdrEntry->DdagNode->State = LdrModulesReadyToRun;
			}
		}
	}
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpCompleteMapModule(PLDRP_LOAD_CONTEXT LoadContext, PIMAGE_NT_HEADERS OutHeaders, NTSTATUS Status)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpProcessMappedModule(PLDR_DATA_TABLE_ENTRY LdrEntry, ULONG64 Flags, ULONG Unknown)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpCorProcessImports(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapAndSnapDependency(PLDRP_LOAD_CONTEXT LoadContext)
{
	// TO DO.

	return STATUS_SUCCESS;
}



NTSTATUS __fastcall LOADLIBRARY::fLdrpPrepareModuleForExecution(PLDR_DATA_TABLE_ENTRY LdrEntry, NTSTATUS* pStatus)
{
	// TO DO.

	return STATUS_SUCCESS;
}


NTSTATUS __fastcall LOADLIBRARY::fBasepLoadLibraryAsDataFileInternal(PUNICODE_STRING DllName, PWSTR Path, PWSTR Unknown, DWORD dwFlags, HMODULE* pBaseOfLoadedModule)
{
	// TO DO.
	
	return STATUS_SUCCESS;
}

NTSTATUS LOADLIBRARY::Unload()
{
	if (DllHandle)
	{
		// Yes.
		if (!FreeLibrary(DllHandle))
			return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}