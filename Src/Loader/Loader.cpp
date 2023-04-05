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

	NTSTATUS Status = STATUS_SUCCESS;
	if (Status = Load(), NT_SUCCESS(Status))
	{
		WID_DBG(TEXT("[WID] >> (Path: %s), (Flags: %lu) load successful.\n"), DllPath, Flags);
		WID_DBG(TEXT("[WID] >> Base address: %p.\n"), DllHandle);
	}
	else
	{
		WID_DBG(TEXT("[WID] >> (Path: %s), (Flags: %lu) load failed, err: 0x%X.\n"), DllPath, Flags, Status);
	}
}

LOADLIBRARY::~LOADLIBRARY()
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (Status = Unload(), NT_SUCCESS(Status))
	{
		WID_DBG(TEXT("[WID] >> (Path: %s), (Flags: %lu) unload successful.\n"), CreationInfo.DllPath, CreationInfo.Flags);
	}
	else
	{
		WID_DBG(TEXT("[WID] >> (Path: %s), (Flags: %lu) unload failed, err: 0x%X.\n"), CreationInfo.DllPath, CreationInfo.Flags, Status);
	}
}


NTSTATUS LOADLIBRARY::Load()
{
	if (!CreationInfo.DllPath)
		return STATUS_INVALID_PARAMETER;

	switch (CreationInfo.LoadType)
	{
	case LOADTYPE::DEFAULT:
	//case LOADTYPE::HIDDEN:
		DllHandle = fLoadLibrary(CreationInfo.DllPath);
		if (!DllHandle || DllHandle == INVALID_HANDLE_VALUE)
			break;
		return STATUS_SUCCESS;
	case LOADTYPE::HIDDEN:
		WID_DBG(TEXT("[WID] >> Hidden loading isn't available currently.\n"));
	default:
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_UNSUCCESSFUL;
}



HMODULE __fastcall LOADLIBRARY::fLoadLibrary(PTCHAR lpLibFileName) // CHECKED.
{
#ifndef _UNICODE
	return fLoadLibraryA(lpLibFileName);
#else
	return fLoadLibraryW(lpLibFileName);
#endif
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryA(LPCSTR lpLibFileName) // CHECKED.
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
	PCHAR Heap = (PCHAR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, *KernelBaseGlobalData, MAX_PATH);
	if (!Heap)
		return fLoadLibraryExA(lpLibFileName, 0, 0);

	HMODULE Module;
	// Heap receives the Windows path (def: C:\Windows)

	// The BufferSize check made against GetWindowsDirectoryA is to see if it actually received. If it's bigger than BufferSize 
	// then GetWindowsDirectoryA returned the size needed (in summary it fails)

	// If this check doesn't fail '\twain_32.dll' is appended to the Windows path (def: C:\Windows\twain_32.dll)
	// Then this final module is loaded into the program.
	// If it can't load, it tries to load it directly and returns from there.
	if (GetWindowsDirectoryA(Heap, 0xF7) - 1 > 0xF5 ||
		(strncat_s(Heap, MAX_PATH, "\\twain_32.dll", strlen("\\twain_32.dll")), (Module = fLoadLibraryA(Heap)) == 0))
	{
		RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
		return fLoadLibraryExA(lpLibFileName, 0, 0);
	}

	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
	return Module;
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryW(LPCWSTR lpLibFileName) // CHECKED.
{
	return fLoadLibraryExW(lpLibFileName, 0, 0);
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) // CHECKED.
{	
	UNICODE_STRING Unicode;
	if (!Basep8BitStringToDynamicUnicodeString(&Unicode, lpLibFileName))
		return NULL;

	HMODULE Module = fLoadLibraryExW(Unicode.Buffer, hFile, dwFlags);
	RtlFreeUnicodeString(&Unicode);
	return Module;
}

HMODULE __fastcall LOADLIBRARY::fLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) // CHECKED.
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
	if (!NT_SUCCESS(Status))
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
	if (!NT_SUCCESS(Status))
	{
		BaseSetLastNTError(Status);
		return NULL;
	}

	// First step into loading a module as datafile.
	Status = fBasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, dwFlags, &BaseOfLoadedDll);
	// If the Status is only success (excludes warnings) AND if the module is image resource, loads again. I don't know why.
	if (NT_SUCCESS(Status + 0x80000000) && Status != STATUS_NO_SUCH_FILE && (dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE))
	{
		if (DatafileFlags)
			Status = fBasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, DatafileFlags, &BaseOfLoadedDll);
	}

	RtlReleasePath(Path);
	BaseSetLastNTError(Status);
	return NULL;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrLoadDll(PWSTR DllPath, PULONG pFlags, PUNICODE_STRING DllName, PVOID* BaseAddress) // CHECKED.
{
	NTSTATUS Status;

	// DllPath can also be used as Flags if called from LoadLibraryExW

	UINT_PTR FlagUsed = 0;
	if (pFlags)
	{
		// Only flags that could go through *LoadLibraryExW* were;
		// CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2)
		// LOAD_PACKAGED_LIBRARY (0x4)
		// CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x800000)
		// CNVTD_LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY (0x80000000)
		// So I am assuming the rest of the flags are 0.

		UINT_PTR ActualFlags = *pFlags;
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

	if ((*LdrpPolicyBits & 4) == 0 && ((USHORT)DllPath & LLDLL_401) == LLDLL_401)
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
		// LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 601, "LdrLoadDll", 0, &LdrEntry[176]);
		WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x259, "LdrLoadDll", 0, "Nonpackaged process attempted to load a packaged DLL.\n"); )
		Status = STATUS_NO_APPLICATION_PACKAGE;
	}

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x279, "LdrLoadDll", 4, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDll(PUNICODE_STRING DllName, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, LDR_DATA_TABLE_ENTRY** DllEntry) // CHECKED.
{
	NTSTATUS Status;

	WID_HIDDEN( LdrpLogDllState(0, DllName, 0x14A8); )

	// Flags is passed by value so no need to create a backup, it's already a backup by itself.
	// MOST FLAGS = CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80)

	// Creates a new unicode_string and allocates it some buffer.
	UNICODE_STRING FullDllPath;
	WCHAR Buffer[128];
	FullDllPath.Length = 0;
	FullDllPath.MaximumLength = MAX_PATH - 4;
	FullDllPath.Buffer = Buffer;
	Buffer[0] = 0;
	 
	// Returns the Absolute path
	// If a non-relative path was given then the flags will be ORed with LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) | LOAD_LIBRARY_SEARCH_USER_DIRS (0x400)
	// resulting in the MOST FLAGS being:
	// CNVTD_DONT_RESOLVE_DLL_REFERENCES (0x2) | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) | LOAD_LIBRARY_REQUIRE_SIGNED_TARGET (0x80) |
	// LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) | LOAD_LIBRARY_SEARCH_USER_DIRS (0x400)
	Status = LdrpPreprocessDllName(DllName, &FullDllPath, 0, &Flags);

	if (NT_SUCCESS(Status))
		// A even deeper function, by far we can see Windows is kinda all *wrapped* around each other.

		// This function is responsible for the linking issue.
		fLdrpLoadDllInternal(&FullDllPath, DllPathInited, Flags, ImageDll, 0, 0, DllEntry, &Status, 0);

	if (Buffer != FullDllPath.Buffer)
		NtdllpFreeStringRoutine(FullDllPath.Buffer);

	// I don't see no point in this but anyways.
	FullDllPath.Length = 0;
	FullDllPath.MaximumLength = MAX_PATH - 4;
	FullDllPath.Buffer = Buffer;
	Buffer[0] = 0;
	WID_HIDDEN( LdrpLogDllState(0, DllName, 0x14A9); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDllInternal(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus, ULONG Zero)  // CHECKED. // This function is responsible for the linking issue.
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

	bool IsWorkerThread = false;
	do
	{
		*DllEntry = 0;
		LdrEntry = LdrEntry2;

		// This will go in.
		if (LdrFlags != (PackagedBinary | LoadNotificationsSent))
		{
			// This function does some prior setup, incrementing the module load count is done inside here.
			Status = LdrpFastpthReloadedDll(FullPath, Flags, LdrEntry2, DllEntry); // returns STATUS_DLL_NOT_FOUND in normal circumstances.

			// If not an actual nt success (excludes warnings)
			if (!NT_SUCCESS((LONG)(Status + 0x80000000)) || Status == STATUS_IMAGE_LOADED_AS_PATCH_IMAGE)
			{
				*pStatus = Status;
				break;
			}
		}

		IsWorkerThread = ((NtCurrentTeb()->SameTebFlags & LoadOwner) == 0);
		if (IsWorkerThread)
			LdrpDrainWorkQueue(WaitLoadComplete);

		// This won't go in so we can ignore it. I still did simplifying though.
		// Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one.
		if (LdrFlags == (PackagedBinary | LoadNotificationsSent))
		{
			Status = LdrpFindLoadedDllByHandle(Zero, &LdrEntry, 0);
			if (!NT_SUCCESS(Status))
			{
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

				if (FullPath->Buffer)
					LdrpFreeUnicodeString(FullPath);

				*pStatus = Status;

				if (IsWorkerThread)
					LdrpDropLastInProgressCount();

				break;
			}

			// LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x3FA, "LdrpLoadDllInternal", 2u, &::LdrEntry[232], FullPath);
			WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x3FA, "LdrpLoadDllInternal", 2, "Loading patch image: %wZ\n", FullPath); )
		}

		// Opens a token to the current thread and sets GLOBAL variable LdrpMainThreadToken with that token.
		LdrpThreadTokenSetMainThreadToken(); // returns STATUS_NO_TOKEN in normal circumstances.

		LDR_DATA_TABLE_ENTRY* pLdrEntryLoaded = 0;
		// This will go in by the first check LdrEntry2 because it was sent as 0 in LdrpLoadDll.
		if (!LdrEntry || !IsWorkerThread || LdrEntry->DdagNode->LoadCount)
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

			//Status = LdrpFindOrPrepareLoadingModule(FullPath, DllPathInited, Flags, LdrFlags, LdrEntry, &pLdrEntryLoaded, pStatus);
			Status = LdrpFindOrPrepareLoadingModule(FullPath, DllPathInited, Flags, LdrFlags, LdrEntry, &pLdrEntryLoaded, pStatus);
			if (Status == STATUS_DLL_NOT_FOUND)
				// Even if the DllMain call succeeds, there's still runtime bugs on the dll side, like the dll not being able to unload itself and such. So I still got
				// a lot of work to do.
				fLdrpProcessWork(pLdrEntryLoaded->LoadContext, TRUE);
			else if (Status != STATUS_RETRY && !NT_SUCCESS(Status))
				*pStatus = Status;
		}
		else
		{
			*pStatus = STATUS_DLL_NOT_FOUND;
		}

		LdrpDrainWorkQueue(WaitWorkComplete);

		if (*LdrpMainThreadToken)
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

				Status = fLdrpPrepareModuleForExecution(pLdrEntryLoaded, pStatus);
				*pStatus = Status;
				if (NT_SUCCESS(Status))
				{
					Status = LdrpBuildForwarderLink(LdrEntry, pLdrEntryLoaded);
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
						if (!NT_SUCCESS(Status))
						{
							//UNICODE_STRING Names[4];
							//Names[0] = pLdrEntryLoaded->FullDllName;
							//WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x4AF, "LdrpLoadDllInternal", 0, "Applying patch \"%wZ\" failed\n", Names); )
							WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x4AF, "LdrpLoadDllInternal", 0, "Applying patch \"%wZ\" failed\n", pLdrEntryLoaded->FullDllName); )
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
	
	if (IsWorkerThread)
		LdrpDropLastInProgressCount();

	// LoadNotificationsSent (0x8) | PackagedBinary (0x1)
	// Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one too.
	if (LdrFlags == (LoadNotificationsSent | PackagedBinary) && LdrEntry)
		LdrpDereferenceModule(LdrEntry);

	Status = *pStatus;
	WID_HIDDEN( Status = LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x52E, "LdrpLoadDllInternal", 4, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpProcessWork(PLDRP_LOAD_CONTEXT LoadContext, BOOLEAN IsLoadOwner) // CHECKED.
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
		if ((UINT_PTR)LoadContext->WorkQueueListEntry.Flink[9].Blink[3].Blink & UINT_MAX)
		{
			Status = fLdrpSnapModule(LoadContext);
		}
		else
		{
			if (LoadContext->Flags & 0x100000)
			{
				Status = fLdrpMapDllRetry(LoadContext);
			}
			// We will continue from here since we have the LOAD_LIBRARY_SEARCH_APPLICATION_DIR flag, and also the function name is exactly representing
			// what we are expecting to happen.
			else if (LoadContext->Flags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
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

				//PLDR_DATA_TABLE_ENTRY DllEntry = (PLDR_DATA_TABLE_ENTRY)LoadContext->WorkQueueListEntry.Flink;
				LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
				if (DllEntry->FlagGroup[0] & ProcessStaticImport)
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
		if (*LdrpWorkQueue != (LIST_ENTRY*)LdrpWorkQueue || (SetWorkCompleteEvent = TRUE, *LdrpWorkInProgress != 1))
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
	NTSTATUS Status = STATUS_SUCCESS;
	NTSTATUS Status_2 = STATUS_SUCCESS;
	NTSTATUS Status_3 = STATUS_SUCCESS;
	NTSTATUS NtStatus = STATUS_SUCCESS;

	FUNCTION_TABLE_DATA FunctionTableData{};
	FUNCTION_TABLE_DATA FunctionTableData2{};
	

	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	PIMAGE_DOS_HEADER DllBase = DllEntry->DllBase;
	PUNICODE_STRING FullDllName = &DllEntry->FullDllName;
	WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllBase, &DllEntry->FullDllName, 0x14A6u); )
	LdrpHandlePendingModuleReplaced(LoadContext);

	PIMAGE_DOS_HEADER DosHeaders[8];
	memset(DosHeaders, 0, sizeof(DosHeaders));

	PIMAGE_SECTION_HEADER SectionHeader = nullptr;
	LONG DosHeaderIdx = 0;
	ULONG v93 = 0;

	BOOL SomeStatus = FALSE;
	LDR_DATA_TABLE_ENTRY* DllEntry_2 = nullptr;
	LDR_DATA_TABLE_ENTRY* DllEntry_3 = nullptr;

	PCHAR GuardCFArray = nullptr;
	PCHAR GuardCFArray2VA = nullptr;

	PIMAGE_SECTION_HEADER SectionHeader_2;
	while (TRUE)
	{
		SomeStatus = TRUE;
		ULONG OriginalIATProtect = LoadContext->OriginalIATProtect;
		if (OriginalIATProtect >= LoadContext->SizeOfIAT)
		{
			Status = fLdrpDoPostSnapWork(LoadContext);
			if (NT_SUCCESS(Status))
			{
				WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllEntry->DllBase, &DllEntry->FullDllName, 0x14A7u); )
				DllEntry->DdagNode->State = LdrModulesSnapped;
			}

			goto SET_LOAD_CONTEXT;
		}

		UINT_PTR OriginalIATProtect_2 = OriginalIATProtect;
		LDR_DATA_TABLE_ENTRY* IdxLdrEntry = LoadContext->IATCheck[OriginalIATProtect];
		DllEntry_2 = IdxLdrEntry;
		DllEntry_3 = IdxLdrEntry;
		if (IdxLdrEntry)
		{
			LDRP_LOAD_CONTEXT* LoadContext_2 = IdxLdrEntry->LoadContext;
			if (LoadContext_2)
			{
				if ((LoadContext_2->Flags & 0x80000) == 0 && CONTAINING_RECORD(LoadContext_2->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) != IdxLdrEntry)
				{
					DllEntry_2 = CONTAINING_RECORD(LoadContext_2->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
					DllEntry_3 = DllEntry_2;
					LoadContext_2->WorkQueueListEntry.Flink = &IdxLdrEntry->InLoadOrderLinks;
				}
			}
		}

		LDR_DATA_TABLE_ENTRY* IdxLdrEntry_2 = LoadContext->IATCheck[OriginalIATProtect_2];
		if (IdxLdrEntry_2 != DllEntry_2)
		{
			LdrpFreeReplacedModule(IdxLdrEntry_2);
			LoadContext->IATCheck[OriginalIATProtect_2] = DllEntry_2;
		}

		ULONG* GuardCFCheckFunctionPointer = (ULONG*)LoadContext->GuardCFCheckFunctionPointer;
		UINT_PTR GuardCFArrayVA = GuardCFCheckFunctionPointer[5 * OriginalIATProtect_2];
		GuardCFArray = (char*)DllBase + GuardCFArrayVA;
		GuardCFArray2VA = (char*)DllBase + GuardCFCheckFunctionPointer[5 * OriginalIATProtect_2 + 4];
		if (!(DWORD)GuardCFArrayVA || (unsigned int)GuardCFArrayVA > DllEntry->SizeOfImage)
			GuardCFArray = (char*)DllBase + GuardCFCheckFunctionPointer[5 * OriginalIATProtect_2 + 4];

		if (DllEntry_2)
			break;

	INCREMENT_IAT_PROTECT:
		++LoadContext->OriginalIATProtect;
	}

	PIMAGE_DOS_HEADER DllBase_3 = DllEntry_2->DllBase;
	PIMAGE_DOS_HEADER DllBase_4 = DllBase_3;
	BOOLEAN DllBaseUnknownFlagCheck = TRUE;
	PIMAGE_DOS_HEADER DllBase_5 = DllBase_3;
	PIMAGE_NT_HEADERS32 pNtHeader = nullptr;
	PIMAGE_EXPORT_DIRECTORY pImageExportDir_2 = nullptr;
	if (((BYTE)DllBase_3 & 3) != 0)
	{
		DllBase_5 = (PIMAGE_DOS_HEADER)((UINT_PTR)DllBase_3 & 0xFFFFFFFFFFFFFFFC);
		DllBaseUnknownFlagCheck = ((BYTE)DllBase_3 & 1) == 0;
	}

	NtStatus = RtlImageNtHeaderEx(1u, DllBase_5, 0i64, (PIMAGE_NT_HEADERS*)&pNtHeader);
	if (!pNtHeader)
		goto ZERO_IMAGE_EXPORT_DIR_2;

	WORD Magic = pNtHeader->OptionalHeader.Magic;
	ULONG DirectorySize = 0;
	UINT_PTR DirectoryVA = 0;

	// For 32-bit apps
	// Checks if it's not a 32-bit app
	if (Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		// For 64-bit apps
		if (Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			DirectoryVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
			
			if ((DWORD)DirectoryVA)
			{
				DirectorySize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
				if (!DllBaseUnknownFlagCheck && (ULONG)DirectoryVA >= pNtHeader->OptionalHeader.SizeOfHeaders)
				{
					SectionHeader_2 = RtlAddressInSectionTable((PIMAGE_NT_HEADERS)pNtHeader, DllBase_5, (ULONG)DirectoryVA);
					pImageExportDir_2 = (PIMAGE_EXPORT_DIRECTORY)SectionHeader_2;
					NtStatus = STATUS_SUCCESS;
					if (!SectionHeader_2)
						NtStatus = STATUS_INVALID_PARAMETER;

					goto NT_STUFF;
				}

			GET_IMAGE_EXPORT_DIR:
				SectionHeader_2 = (PIMAGE_SECTION_HEADER)((char*)DllBase_5 + DirectoryVA);
				pImageExportDir_2 = (PIMAGE_EXPORT_DIRECTORY)((char*)DllBase_5 + DirectoryVA);
				NtStatus = STATUS_SUCCESS;
				goto NT_STUFF;
			}

			NtStatus = STATUS_NOT_IMPLEMENTED;
		ZERO_IMAGE_EXPORT_DIR_2:
			SectionHeader_2 = nullptr;
			goto NT_STUFF;
		}

	ZERO_IMAGE_EXPORT_DIR:
		NtStatus = STATUS_INVALID_PARAMETER;
		goto ZERO_IMAGE_EXPORT_DIR_2;
	}

	if (!pNtHeader->OptionalHeader.NumberOfRvaAndSizes)
		goto ZERO_IMAGE_EXPORT_DIR;

	DirectoryVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!(DWORD)DirectoryVA)
	{
		NtStatus = STATUS_NOT_IMPLEMENTED;
		goto ZERO_IMAGE_EXPORT_DIR_2;
	}

	DirectorySize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (DllBaseUnknownFlagCheck || (ULONG)DirectoryVA < pNtHeader->OptionalHeader.SizeOfHeaders)
		goto GET_IMAGE_EXPORT_DIR;

	SectionHeader_2 = RtlAddressInSectionTable((PIMAGE_NT_HEADERS)pNtHeader, DllBase_5, (ULONG)DirectoryVA);
	pImageExportDir_2 = (PIMAGE_EXPORT_DIRECTORY)SectionHeader_2;
	NtStatus = STATUS_SUCCESS;
	if (!SectionHeader_2)
		NtStatus = STATUS_INVALID_PARAMETER;

NT_STUFF:
	if (!NT_SUCCESS(NtStatus))
	{
		SectionHeader_2 = nullptr;
		pImageExportDir_2 = nullptr;
	}

	if (!SectionHeader_2)
	{
		WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 3278, "LdrpSnapModule", 0, "DLL \"%wZ\" does not contain an export table\n", &DllEntry_3->FullDllName); )
		Status = STATUS_INVALID_IMAGE_FORMAT;
		SomeStatus = TRUE;
		goto SET_LOAD_CONTEXT;
	}

	ULONG i = 0;
	BOOLEAN IsFinalIdx = FALSE;
	for (i = 0; ; ++i)
	{
		IsFinalIdx = i == 8;
		if (i >= 8)
			break;

		PIMAGE_DOS_HEADER IdxDosHeader = DosHeaders[i];
		if (!IdxDosHeader || DllBase_3 == IdxDosHeader)
		{
			IsFinalIdx = i == 8;
			break;
		}
	}

	if (IsFinalIdx || !DosHeaders[i])
	{
		if (LdrControlFlowGuardEnforced())
		{
			if (DllBase_3 < (*stru_199520).ImageBase
				|| DllBase_3 >= (PIMAGE_DOS_HEADER)((char*)(*stru_199520).ImageBase + (*stru_199520).ImageSize))
			{
				RtlpxLookupFunctionTable(DllBase_3, (PIMAGE_RUNTIME_FUNCTION_ENTRY*)&FunctionTableData);
			}
			else
			{
				FunctionTableData = (*stru_199520);
			}

			if (FunctionTableData.ImageBase != DllBase_3)
				goto LABEL_188;
		}

		DosHeaders[DosHeaderIdx] = DllBase_3;
		DosHeaderIdx = ((BYTE)DosHeaderIdx + 1) & 7;
	}

	PCHAR v27 = (CHAR*)&SectionHeader_2->Name[DirectorySize];
	PCHAR v108 = v27;
	UINT_PTR* pFuncAddresses = (UINT_PTR*)((char*)&DllBase_3->e_magic + SectionHeader_2->PointerToLinenumbers);
	UINT_PTR* pFuncAddresses_2 = pFuncAddresses;
	DWORD NumberNames = SectionHeader_2->PointerToRelocations;
	DWORD NumberNames_2 = NumberNames;
	PCHAR pAddressNames = (char*)DllBase_3 + *(unsigned int*)&SectionHeader_2->NumberOfRelocations;
	PCHAR pAddressNames_2 = pAddressNames;
	PSHORT pNameOrdinals = (SHORT*)((char*)DllBase_3 + SectionHeader_2->Characteristics);
	UINT_PTR IATIdx = 8 * (*(&LoadContext->OriginalIATProtect + 1));
	UINT_PTR* v32 = (UINT_PTR*)&GuardCFArray[IATIdx];
	UINT_PTR* v33 = (UINT_PTR*)&GuardCFArray2VA[IATIdx];

	UINT_PTR v36 = 0;
	PCHAR v104 = 0;
	while (TRUE)
	{
		UINT_PTR* v106 = v33;
		UINT_PTR* v105 = v32;
		UINT_PTR v34 = *v32;
		if (!*v32)
		{
			*(&LoadContext->OriginalIATProtect + 1) = 0;
			goto INCREMENT_IAT_PROTECT;
		}

		Status = STATUS_PROCEDURE_NOT_FOUND;
		v36 = v34 >> 63;
		UINT_PTR v103 = v34 >> 63;
		PCHAR FunctionIdxAddress = (PCHAR)0xFFFFFFFFFFBADD11;
		ULONG FunctionIdx = 0;
		v104 = 0;
		if ((v34 & 0x8000000000000000) != 0)
		{
			v93 = (USHORT)v34;
			FunctionIdx = (USHORT)v34 - SectionHeader_2->SizeOfRawData;
		}
		else
		{
			PCHAR v38 = (char*)DllEntry->DllBase + (ULONG)v34;
			v104 = v38 + 2;
			if ((LoadContext->Flags & 0x2000000) != 0)
			{
				PCHAR v79 = LdrpCheckRedirection(DllEntry, DllEntry_3, v38 + 2);
				FunctionIdxAddress = v79;
				if (v79 != (PCHAR)0xFFFFFFFFFFBADD11)
				{
					WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 3375, "LdrpSnapModule", 2u, "Import '%s' of DLL '%wZ' is redirected to 0x%p", v38 + 2, FullDllName, v79); )
					SectionHeader_2 = (PIMAGE_SECTION_HEADER)pImageExportDir_2;
					goto LABEL_54;
				}
				pAddressNames = pAddressNames_2;
				NumberNames = NumberNames_2;
			}

			LONG NameOrdinalIdx = *(USHORT*)v38;
			LONG v40 = 0;
			LONG NumberNamesM1 = NumberNames - 1;
			if (NameOrdinalIdx >= NumberNames)
				NameOrdinalIdx = NumberNamesM1 / 2;

			if (NumberNamesM1 < 0)
			{
			SET_SOMESTATUS_LOG_RETURN:
				SomeStatus = TRUE;
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 2190, "LdrpNameToOrdinal", 1u, "Procedure \"%s\" could not be located in DLL at base 0x%p.\n", v38 + 2, DllBase_3); )
				SectionHeader_2 = (PIMAGE_SECTION_HEADER)pImageExportDir_2;
				goto CHECK_STATUS_GOON;
			}

			LONG v45 = 0;
			while (TRUE)
			{
				PBOOLEAN v42 = (BOOLEAN*)(v38 + 2);
				BOOLEAN v44 = FALSE;
				PCHAR Names = (PCHAR)((char*)DllBase_3 + *(unsigned int*)&pAddressNames[4 * NameOrdinalIdx] - (v38 + 2));
				while (TRUE)
				{
					v44 = *v42;
					if (*v42 != Names[(UINT_PTR)v42])
						break;

					++v42;
					if (!v44)
					{
						v45 = 0;
						goto LABEL_41;
					}
				}

				v45 = v44 < (unsigned int)Names[(UINT_PTR)v42] ? -1 : 1;
			LABEL_41:
				if (!v45)
					break;

				LONG NameOrdinalIdxM1 = NameOrdinalIdx - 1;
				if (v45 >= 0)
					NameOrdinalIdxM1 = NumberNamesM1;

				NumberNamesM1 = NameOrdinalIdxM1;
				if (v45 >= 0)
					v40 = NameOrdinalIdx + 1;

				NameOrdinalIdx = (v40 + NameOrdinalIdxM1) / 2;
				pAddressNames = pAddressNames_2;
				if (NameOrdinalIdxM1 < v40)
					goto SET_SOMESTATUS_LOG_RETURN;
			}

			FunctionIdx = (USHORT)pNameOrdinals[NameOrdinalIdx];
			SectionHeader_2 = (PIMAGE_SECTION_HEADER)pImageExportDir_2;
			pFuncAddresses = pFuncAddresses_2;
			v27 = v108;
		}

		if (FunctionIdx >= SectionHeader_2->PointerToRawData)
		{
		LABEL_52:
			SomeStatus = TRUE;
			goto CHECK_STATUS_GOON;
		}

		_mm_lfence();
		UINT_PTR FunctionIdxAddressVA = *((ULONG*)pFuncAddresses + FunctionIdx);
		if (!(DWORD)FunctionIdxAddressVA)
		{
			Status = STATUS_PROCEDURE_NOT_FOUND;
			goto LABEL_52;
		}

		FunctionIdxAddress = (char*)DllBase_3 + FunctionIdxAddressVA;
		PCHAR FunctionIdxAddress_2 = (char*)DllBase_3 + FunctionIdxAddressVA;
		Status = STATUS_SUCCESS;
		if ((char*)DllBase_3 + FunctionIdxAddressVA <= (char*)SectionHeader_2 || FunctionIdxAddress >= v27)
			goto LABEL_52;

		LDR_DATA_TABLE_ENTRY* NtLdrEntry = DllEntry_3;
		PCHAR FunctionIdxAddress_3 = (char*)DllBase_3 + FunctionIdxAddressVA;
		pNtHeader = nullptr;
		LDR_DATA_TABLE_ENTRY* NtLdrEntry_2 = nullptr;
		LDRP_LOAD_CONTEXT* LoadContext_3 = DllEntry->LoadContext;
		LDRP_LOAD_CONTEXT* v111 = LoadContext_3;
		PVOID v101 = nullptr;

		STRING SourceString = {};
		PCHAR SourceBuffer = SourceString.Buffer;
		USHORT SourceLength = SourceString.Length;
		while (TRUE)
		{
			PCHAR StringToBeHashed = 0;
			PCHAR DotOccurence = strrchr(FunctionIdxAddress_3, '.');
			if (!DotOccurence || (unsigned __int64)(DotOccurence - FunctionIdxAddress_3) > 0xFFFF)
				goto LABEL_169;

			SourceBuffer = FunctionIdxAddress_3;
			SourceString.Buffer = FunctionIdxAddress_3;
			SourceLength = (WORD)DotOccurence - (WORD)FunctionIdxAddress_3;
			SourceString.Length = (WORD)DotOccurence - (WORD)FunctionIdxAddress_3;
			SourceString.MaximumLength = (WORD)DotOccurence - (WORD)FunctionIdxAddress_3;
			if (DotOccurence[1] != '#')
			{
				StringToBeHashed = DotOccurence + 1;
				goto LABEL_64;
			}

			PCHAR StringToBeHashed_2 = nullptr;
			ULONG IntValue = 0;
			BOOL SomeStatus_2 = FALSE;
			if (RtlCharToInteger(DotOccurence + 2, 0, &IntValue) >= 0)
			{
				StringToBeHashed = nullptr;
			LABEL_64:
				StringToBeHashed_2 = StringToBeHashed;
				Status = STATUS_SUCCESS;
				SomeStatus_2 = TRUE;
			}
			else
			{
			LABEL_169:
				Status = STATUS_INVALID_IMAGE_FORMAT;
				SomeStatus_2 = FALSE;
				StringToBeHashed = StringToBeHashed_2;
			}
			if (!SomeStatus_2)
				goto LABEL_105;
			// 4 spaces, ldtn, 1 space, l
			if (SourceLength == 5 && (*(DWORD*)SourceBuffer | '    ') == 'ldtn' && ((BYTE)SourceBuffer[4] | ' ') == 'l')
			{
				NtLdrEntry = (LDR_DATA_TABLE_ENTRY*)(*LdrpNtDllDataTableEntry);
				NtLdrEntry_2 = (LDR_DATA_TABLE_ENTRY*)(*LdrpNtDllDataTableEntry);
			}
			else
			{
				Status = LdrpLoadDependentModuleA((PUNICODE_STRING)&SourceString, LoadContext_3, NtLdrEntry, 1, &NtLdrEntry_2, (UINT_PTR)&v101);
				SomeStatus = TRUE;
				if (!NT_SUCCESS(Status) || Status == STATUS_PENDING)
					goto LOAD_DEPENDENTA_FAILED;

				NtLdrEntry = NtLdrEntry_2;
				SourceBuffer = SourceString.Buffer;
				SourceLength = SourceString.Length;
			}

			PCHAR v85 = 0;
			if ((DllEntry->LoadContext->Flags & 0x2000000) != 0)
			{
				if (StringToBeHashed)
				{
					FunctionIdxAddress_3 = LdrpCheckRedirection(DllEntry, NtLdrEntry, StringToBeHashed);
					v85 = FunctionIdxAddress_3;
					if (FunctionIdxAddress_3 != (PCHAR)0xFFFFFFFFFFBADD11)
					{
						Status = STATUS_SUCCESS;
						SomeStatus = TRUE;
						goto LABEL_109;
					}
				}
			}

			PIMAGE_DOS_HEADER NtBase = NtLdrEntry->DllBase;
			BOOLEAN SomeNtCheck = TRUE;
			PIMAGE_DOS_HEADER NtBase_2 = NtBase;
			PIMAGE_NT_HEADERS OutHeaders = nullptr;
			if (((BYTE)NtBase & 3) != 0)
			{
				NtBase_2 = (PIMAGE_DOS_HEADER)((UINT_PTR)NtBase & 0xFFFFFFFFFFFFFFFC);
				SomeNtCheck = ((BYTE)NtBase & 1) == 0;
			}

			Status_2 = RtlImageNtHeaderEx(1u, NtBase_2, 0, &OutHeaders);

			ULONG Size = 0;
			if (OutHeaders)
			{
				WORD Magic_2 = OutHeaders->OptionalHeader.Magic;
				UINT_PTR NtExportDirVA = 0;
				if (Magic_2 != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					if (Magic_2 == IMAGE_NT_OPTIONAL_HDR64_MAGIC && OutHeaders->OptionalHeader.NumberOfRvaAndSizes)
					{
						NtExportDirVA = OutHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
						if (!(DWORD)NtExportDirVA)
						{
							Status_2 = STATUS_NOT_IMPLEMENTED;
							goto CHECK_NT_EXPORTDIR;
						}

						Size = OutHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
						if (!SomeNtCheck && (unsigned int)NtExportDirVA >= OutHeaders->OptionalHeader.SizeOfHeaders)
						{
							SectionHeader = RtlAddressInSectionTable(OutHeaders, NtBase_2, (unsigned int)NtExportDirVA);
							Status_2 = 0;
							if (!SectionHeader)
								Status_2 = STATUS_INVALID_PARAMETER;
							goto CHECK_NT_EXPORTDIR;
						}

					GET_NT_EXPORTDIR:
						SectionHeader = (PIMAGE_SECTION_HEADER)((char*)NtBase_2 + NtExportDirVA);
						Status_2 = 0;
						goto CHECK_NT_EXPORTDIR;
					}
				FAIL_NTSTATUS:
					Status_2 = STATUS_INVALID_PARAMETER;
					goto CHECK_NT_EXPORTDIR;
				}
				if (!(OutHeaders->OptionalHeader.SizeOfHeapReserve & 0xFFFFFFFF00000000))
					goto FAIL_NTSTATUS;

				NtExportDirVA = (OutHeaders->OptionalHeader.SizeOfHeapCommit & UINT_MAX);
				if (!(DWORD)NtExportDirVA)
				{
					Status_2 = STATUS_NOT_IMPLEMENTED;
					goto CHECK_NT_EXPORTDIR;
				}

				Size = (OutHeaders->OptionalHeader.SizeOfHeapCommit & 0xFFFFFFFF00000000);
				if (SomeNtCheck || (unsigned int)NtExportDirVA < OutHeaders->OptionalHeader.SizeOfHeaders)
					goto GET_NT_EXPORTDIR;

				SectionHeader = RtlAddressInSectionTable(OutHeaders, NtBase_2, (unsigned int)NtExportDirVA);
				Status_2 = 0;
				if (!SectionHeader)
					Status_2 = STATUS_INVALID_PARAMETER;
			}
		CHECK_NT_EXPORTDIR:
			if (!NT_SUCCESS(Status_2))
				SectionHeader = nullptr;

			if (!SectionHeader)
			{
				Status = STATUS_PROCEDURE_NOT_FOUND;
			LABEL_192:
				SectionHeader = nullptr;
			LABEL_105:
				SomeStatus = TRUE;
				goto LOAD_DEPENDENTA_FAILED;
			}

			PCHAR v64 = StringToBeHashed_2;
			ULONG v73 = 0;
			if (StringToBeHashed_2)
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 827, "LdrpGetProcedureAddress", 2u, "Locating procedure \"%s\" by name\n", StringToBeHashed_2); )
				LONG NameIdxP1 = 0;
				LONG NumberOfNames = SectionHeader->PointerToRelocations - 1;
				LONG NameIdx = NumberOfNames / 2;
				if (NumberOfNames >= 0)
				{
					LONG v71 = 0;
					BOOLEAN v70 = 0;
					while (TRUE)
					{
						PCHAR v68 = StringToBeHashed_2;
						INT_PTR v69 = (char*)NtBase + *(unsigned int*)((char*)&NtBase->e_magic + 4 * NameIdx + *(unsigned int*)&SectionHeader->NumberOfRelocations) - StringToBeHashed_2;
						while (TRUE)
						{
							v70 = *v68;
							if (*v68 != v68[v69])
								break;

							++v68;
							if (!v70)
							{
								v71 = 0;
								goto LABEL_89;
							}
						}

						v71 = v70 < (BOOLEAN)v68[v69] ? -1 : 1;
					LABEL_89:
						if (!v71)
							break;

						LONG v72 = NameIdx - 1;
						if (v71 >= 0)
							v72 = NumberOfNames;

						NumberOfNames = v72;
						if (v71 >= 0)
							NameIdxP1 = NameIdx + 1;

						NameIdx = (NameIdxP1 + v72) / 2;
						if (v72 < NameIdxP1)
							goto LABEL_187;
					}
					v73 = *(unsigned __int16*)((char*)&NtBase->e_magic + 2 * NameIdx + SectionHeader->Characteristics);
					v64 = StringToBeHashed_2;
					goto LABEL_97;
				}
			LABEL_187:
				SomeStatus = TRUE;
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 2190, "LdrpNameToOrdinal", 1u, "Procedure \"%s\" could not be located in DLL at base 0x%p.\n", StringToBeHashed_2, NtBase); )

				Status = STATUS_PROCEDURE_NOT_FOUND;
				SectionHeader = nullptr;
			LOAD_DEPENDENTA_FAILED:
				FunctionIdxAddress_3 = v85;
				goto LABEL_107;
			}

			ULONG v78 = IntValue;
			PVOID v83 = (PVOID)IntValue;
			WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 0x34D, "LdrpGetProcedureAddress", 2u, "Loading procedure 0x%lx by ordinal\n", v83); )
			if (!v78)
			{
				Status = STATUS_INVALID_PARAMETER;
				goto LABEL_192;
			}

			v73 = v78 - SectionHeader->SizeOfRawData;
		LABEL_97:
			if (v73 >= SectionHeader->PointerToRawData)
			{
				SectionHeader = nullptr;
				Status = (v64 != nullptr) - 0x3FFFFEC8;
				goto LABEL_105;
			}

			FunctionIdxAddress_3 = (char*)NtBase + *(unsigned int*)((char*)&NtBase->e_magic + 4 * v73 + SectionHeader->PointerToLinenumbers);
			v85 = FunctionIdxAddress_3;
			if (FunctionIdxAddress_3 < (PCHAR)SectionHeader || FunctionIdxAddress_3 >= (PCHAR)&SectionHeader->Name[Size])
			{
				SectionHeader = nullptr;
				Status = STATUS_SUCCESS;
				PIMAGE_RUNTIME_FUNCTION_ENTRY v74 = (PIMAGE_RUNTIME_FUNCTION_ENTRY)NtLdrEntry->DllBase;
				if (!*qword_1993B8 || (*dword_19939C & 1))
					goto LABEL_105;

				if ((PIMAGE_DOS_HEADER)v74 < (*stru_199520).ImageBase || v74 >= (PIMAGE_RUNTIME_FUNCTION_ENTRY)((char*)(*stru_199520).ImageBase + (*stru_199520).ImageSize))
				{
					RtlpxLookupFunctionTable(NtLdrEntry->DllBase, (PIMAGE_RUNTIME_FUNCTION_ENTRY*)&FunctionTableData2);
				}
				else
				{
					FunctionTableData2 = *stru_199520;
				}

				if ((PIMAGE_RUNTIME_FUNCTION_ENTRY)FunctionTableData2.ImageBase == v74)
					goto LABEL_105;

			LABEL_188:
				__fastfail(0x18u);
			}

			pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pNtHeader + 1);
			SectionHeader = 0;
			if ((DWORD)pNtHeader != 32)
			{
				LoadContext_3 = v111;
				continue;
			}

			break;
		}

		Status = STATUS_INVALID_IMAGE_FORMAT;
		SomeStatus = TRUE;
	LABEL_107:
		if (v101)
			RtlFreeHeap(*LdrpHeap, 0, v101);

	LABEL_109:
		if (Status == STATUS_PENDING)
			return STATUS_SUCCESS;

		DllBase_3 = DllBase_4;
		v36 = (BYTE)v103;
		if (!NT_SUCCESS(Status))
			FunctionIdxAddress = FunctionIdxAddress_2;
		else
			FunctionIdxAddress = FunctionIdxAddress_3;

		SectionHeader_2 = (PIMAGE_SECTION_HEADER)pImageExportDir_2;
	CHECK_STATUS_GOON:
		if (NT_SUCCESS(Status))
		{
		LABEL_54:
			UINT_PTR* v49 = v106;
			*v106 = (UINT_PTR)FunctionIdxAddress;
			v32 = v105 + 1;
			v33 = v49 + 1;
			++(*(&LoadContext->OriginalIATProtect + 1));
			pAddressNames = pAddressNames_2;
			NumberNames = NumberNames_2;
			pFuncAddresses = pFuncAddresses_2;
			v27 = v108;
			continue;
		}
		break;
	}

	LDRP_LOAD_CONTEXT* LoadContext_4 = nullptr;
	if (Status != STATUS_PROCEDURE_NOT_FOUND && Status != STATUS_DLL_NOT_FOUND)
	{
	SET_LOAD_CONTEXT:
		LoadContext_4 = LoadContext;
		goto GET_IMAGEBASE_RETURN;
	}

	PUNICODE_STRING pFullDllName_2 = {};
	if (CompatCachepLookupCdb(DllEntry->FullDllName.Buffer, 128) || CompatCachepLookupCdb(DllEntry_3->FullDllName.Buffer, 128))
	{
		pFullDllName_2 = FullDllName;
		WID_HIDDEN( LdrpLogLoadFailureEtwEvent(FullDllName, (PCHAR)DllEntry_3 + 72, 1, LoadFailure, 0); )
		WID_HIDDEN( LdrpLogLoadFailureEtwEvent(pFullDllName_2, (PCHAR)DllEntry_3 + 72, 1, LoadFailureOperational, 1); )
	}
	else
	{
		pFullDllName_2 = FullDllName;
	}

	UINT_PTR v82 = 0;
	if ((BYTE)v36)
	{
		Status_3 = STATUS_ORDINAL_NOT_FOUND;
		Status = STATUS_ORDINAL_NOT_FOUND;
		v82 = v93;
	}
	else
	{
		Status = STATUS_ENTRYPOINT_NOT_FOUND;
		Status_3 = STATUS_ENTRYPOINT_NOT_FOUND;
		v82 = (UINT_PTR)v104;
	}

	LdrpReportError(pFullDllName_2, v82, (unsigned int)Status_3);
	LoadContext_4 = LoadContext;

GET_IMAGEBASE_RETURN:
	PIMAGE_DOS_HEADER ImageBase = LoadContext_4->ImageBase;
	if (ImageBase)
	{
		NtUnmapViewOfSection((HANDLE)-1ui64, ImageBase);
		LoadContext_4 = LoadContext;
		LoadContext->ImageBase = 0i64;
	}

	if (!NT_SUCCESS(Status))
		SomeStatus = FALSE;

	if (!SomeStatus)
		WID_HIDDEN( LdrpLogError(Status, 0x19u, 0, &LoadContext_4->BaseDllName); )

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpDoPostSnapWork(LDRP_LOAD_CONTEXT* LoadContext)
{
	NTSTATUS Status = STATUS_SUCCESS;

	LDR_DATA_TABLE_ENTRY* DllEntry;
	
	NTSTATUS Status_2;
	UINT_PTR* DllNameLen;
	NTSTATUS Status_3;
	NTSTATUS Status_4;
	ULONG OldAccessProtect;

	DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	if (!LoadContext->pImageImportDescriptor || (Status_2 = ZwProtectVirtualMemory((HANDLE)-1, (PVOID*)&LoadContext->pImageImportDescriptor, &LoadContext->ImageImportDescriptorLen, LoadContext->GuardFlags, &OldAccessProtect), Status = Status_2, Status_2 >= 0))
	{
		DllNameLen = (UINT_PTR*)LoadContext->UnknownFunc;
		if (DllNameLen && *DllNameLen != LoadContext->DllNameLenCompare)
			__fastfail(0x13u);

		if (DllEntry->TlsIndex || (Status_2 = LdrpHandleTlsData(DllEntry), Status = Status_2, Status_2 >= 0))
		{
			if (LdrControlFlowGuardEnforcedWithExportSuppression())
			{
				Status_3 = LdrpUnsuppressAddressTakenIat(DllEntry->DllBase, 0i64, 0i64);
				Status = Status_3;
				if (Status_3 < 0)
				{
					Status_4 = Status_3;
					WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 583, "LdrpDoPostSnapWork", 0, "LdrpDoPostSnapWork:Unable to unsuppress the export suppressed functions that are imported in the DLL based a""t 0x%p.Status = 0x%x\n", DllEntry->DllBase, Status_4); )
				}
			}
			return Status;
		}
	}
	return Status_2;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllRetry(PLDRP_LOAD_CONTEXT LoadContext)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllFullPath(PLDRP_LOAD_CONTEXT LoadContext) // CHECKED.
{
	NTSTATUS Status;
	
	//LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	LDRP_FILENAME_BUFFER FileNameBuffer;	

	FileNameBuffer.pFileName.Buffer = FileNameBuffer.FileName;
	FileNameBuffer.pFileName.Length = 0;
	FileNameBuffer.pFileName.MaximumLength = MAX_PATH - 4;
	FileNameBuffer.FileName[0] = 0;

	// Sets the according members of the DllEntry
	Status = LdrpResolveDllName(LoadContext, &FileNameBuffer, &DllEntry->BaseDllName, &DllEntry->FullDllName, LoadContext->Flags);
	do
	{
		if (LoadContext->UnknownPtr)
		{
			if (!NT_SUCCESS(Status))
				break;
		}
		else
		{
			Status = LdrpAppCompatRedirect(LoadContext, &DllEntry->FullDllName, &DllEntry->BaseDllName, &FileNameBuffer, Status);
			if (!NT_SUCCESS(Status))
				break;

			// Hashes the dll name
			ULONG BaseDllNameHash = LdrpHashUnicodeString(&DllEntry->BaseDllName);
			DllEntry->BaseNameHashValue = BaseDllNameHash;

			LDR_DATA_TABLE_ENTRY* LoadedDll = nullptr;

			// Most likely checks if the dll was already mapped/loaded.
			LdrpFindExistingModule(&DllEntry->BaseDllName, &DllEntry->FullDllName, LoadContext->Flags, BaseDllNameHash, &LoadedDll);
			if (LoadedDll)
			{
				LdrpLoadContextReplaceModule(LoadContext, LoadedDll);
				break;
			}
		}

		// After this function the dll is mapped.
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
	NTSTATUS Status;

	UINT_PTR DependentLoadFlags;
	LDR_UNKSTRUCT* UnkStruct;
	ULONG Flags;
		
	LDR_UNKSTRUCT DllPath;

	LDRP_FILENAME_BUFFER DllNameResolved;
	DllNameResolved.pFileName.Buffer = DllNameResolved.FileName;
	DllNameResolved.pFileName.Length = 0;
	DllNameResolved.pFileName.MaximumLength = MAX_PATH - 4;
	DllNameResolved.FileName[0] = 0;

	LDR_UNKSTRUCT3 UnkStruct3;
	memset(&UnkStruct3, 0, sizeof(UnkStruct3));
	UNICODE_STRING ReturnPath = {};

	LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	LDR_DATA_TABLE_ENTRY* LdrEntry = LoadContext->Entry;
	LDR_DATA_TABLE_ENTRY* LdrEntry2 = nullptr;
	do
	{
		if (LdrEntry && (DependentLoadFlags = LdrEntry->DependentLoadFlags, (((*LdrpPolicyBits & 4) != 0 ? 0x7F00 : 0x7B00) & (ULONG)DependentLoadFlags) != 0))
		{
			LdrpInitializeDllPath(LdrEntry->FullDllName.Buffer, (PWSTR)(DependentLoadFlags & ((-(__int64)((*LdrpPolicyBits & 4) != 0) & 0x400) + 0x7B00) | 1), &DllPath);
			UnkStruct = &DllPath;
		}
		else
		{
			LdrpInitializeDllPath(nullptr, nullptr, &DllPath);
			UnkStruct = LoadContext->UnkStruct;
		}

		BOOL SomeCheck;
		BOOLEAN JumpOut = FALSE;
		while (TRUE)
		{
			UNICODE_STRING BaseDllName;

			BOOL a8 = FALSE;
			Flags = LoadContext->Flags >> 3;
			Flags = (LoadContext->Flags & 8) != 0;
			Status = LdrpSearchPath(LoadContext, UnkStruct, Flags, &ReturnPath, &DllNameResolved, &BaseDllName, &UnkStruct3.String, &a8, &UnkStruct3);
			if (a8)
				DllEntry->Flags |= PackagedBinary;

			if (Status == STATUS_DLL_NOT_FOUND)
				break;

			if (!NT_SUCCESS(Status))
			{
				JumpOut = TRUE;
				break;
			}

		CHECK_LOADCONTEXT:
			SomeCheck = TRUE;
			if (!LoadContext->UnknownPtr)
			{
				Status = LdrpAppCompatRedirect(LoadContext, &UnkStruct3.String, &BaseDllName, &DllNameResolved, Status);
				if (!NT_SUCCESS(Status))
				{
					JumpOut = TRUE;
					break;
				}

				if ((LoadContext->Flags & 0x10000) != 0)
					UnkStruct3.Flags |= PackagedBinary;

				ULONG DllNameHash = LdrpHashUnicodeString(&BaseDllName);
				DllEntry->BaseNameHashValue = DllNameHash;
				Status = LdrpFindExistingModule(&BaseDllName, &UnkStruct3.String, LoadContext->Flags, DllNameHash, &LdrEntry2);
				if (Status != STATUS_DLL_NOT_FOUND)
				{
					JumpOut = TRUE;
					break;
				}
			}
			LdrpFreeUnicodeString(&DllEntry->FullDllName);
			DllEntry->FullDllName = UnkStruct3.String;
			DllEntry->BaseDllName = BaseDllName;
			UnkStruct3.String = {};
			Status = fLdrpMapDllNtFileName(LoadContext, &DllNameResolved);

			if (Status != STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
			{
				JumpOut = TRUE;
				break;
			}

			if (DllNameResolved.FileName != DllNameResolved.pFileName.Buffer)
				NtdllpFreeStringRoutine(DllNameResolved.pFileName.Buffer);

			DllNameResolved.pFileName.Length = 0;
			DllNameResolved.pFileName.MaximumLength = MAX_PATH - 4;
			DllNameResolved.pFileName.Buffer = DllNameResolved.FileName;
			DllNameResolved.FileName[0] = 0;
		}

		if (JumpOut)
			break;

		if (!SomeCheck)
			goto CHECK_LOADCONTEXT;

		Status = STATUS_INVALID_IMAGE_FORMAT;
	} while (FALSE);

	if (LdrEntry2)
	{
		LdrpLoadContextReplaceModule(LoadContext, LdrEntry2);
	}
	else if (LdrpIsSecurityEtwLoggingEnabled())
	{
		LdrpLogEtwDllSearchResults(UnkStruct3.Flags, LoadContext);
	}
	if (DllNameResolved.FileName != DllNameResolved.pFileName.Buffer)
		NtdllpFreeStringRoutine(DllNameResolved.pFileName.Buffer);

	DllNameResolved.pFileName.Length = 0;
	DllNameResolved.pFileName.MaximumLength = MAX_PATH - 4;
	DllNameResolved.pFileName.Buffer = DllNameResolved.FileName;
	DllNameResolved.FileName[0] = 0;
	LdrpFreeUnicodeString(&UnkStruct3.String);
	if (DllPath.IsInitedMaybe)
		RtlReleasePath(DllPath.pInitNameMaybe);

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllNtFileName(PLDRP_LOAD_CONTEXT LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer) // CHECKED.
{
	NTSTATUS Status;

	//LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	INT64 UnknownPtr = LoadContext->UnknownPtr;
	LONG Unknown = 0;
	if (LdrpCheckForRetryLoading(LoadContext, 0))
		return STATUS_RETRY;

	PUNICODE_STRING FullDllName = &DllEntry->FullDllName;
	WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllEntry->DllBase, &DllEntry->FullDllName, 0x14A5); )
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
	PCHAR Unknown2 = 0;
	if (RtlGetCurrentServiceSessionId())
		Unknown2 = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253];
	else
		Unknown2 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2];

	PCHAR NtPathStuff2 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
	if (*Unknown2 && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled))
	{
		//: (char*)0x7FFE0385;
		PCHAR NtPathStuff3 = RtlGetCurrentServiceSessionId() ? (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1 : (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
			
		// 0x20 is SPACE char
		if ((*NtPathStuff3 & ' '))
			LdrpLogEtwEvent(0x1485, -1, 0xFFu, 0xFFu);
	}

	// SYSTEM_FLAGS_INFORMATION
	if ((NtCurrentPeb()->NtGlobalFlag & FLG_ENABLE_KDEBUG_SYMBOL_LOAD))
	{
		WID_HIDDEN( ZwSystemDebugControl(); )
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

		if (Status != STATUS_ACCESS_DENIED || Unknown || !LdrpCheckComponentOnDemandEtwEvent(LoadContext))
			return Status;

		Unknown = TRUE;
	}

	ULONG SigningLevel;
	ULONG AllocationAttributes = 0;
	if	(*LdrpAuditIntegrityContinuity && (Status = LdrpValidateIntegrityContinuity(LoadContext, FileHandle), !NT_SUCCESS(Status)) && *LdrpEnforceIntegrityContinuity || 
		(AllocationAttributes = MEM_IMAGE, (LoadContext->Flags & MEM_IMAGE)) && (NtCurrentPeb()->BitField & IsPackagedProcess) == 0 &&
	  // (Status = LdrpSetModuleSigningLevel(FileHandle, (PLDR_DATA_TABLE_ENTRY)LoadContext->WorkQueueListEntry.Flink, &SigningLevel, 8), !NT_SUCCESS(Status)))
		(Status = LdrpSetModuleSigningLevel(FileHandle, CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), &SigningLevel, 8), !NT_SUCCESS(Status)))
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
	if (*NtPathStuff && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
	{
		if (RtlGetCurrentServiceSessionId())
			NtPathStuff2 = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1;

		// 0x20 is SPACE char.
		if ((*NtPathStuff2 & ' ') != 0)
			WID_HIDDEN( LdrpLogEtwEvent(0x1486, -1, 0xFFu, 0xFFu); )
	}
	if (!*UseWOW64 && (LoadContext->Flags & 0x100) == 0 && (Status = LdrpCodeAuthzCheckDllAllowed(FileNameBuffer, FileHandle), NT_SUCCESS((LONG)(Status + 0x80000000))) && Status != STATUS_NOT_FOUND || (Status = fLdrpMapDllWithSectionHandle(LoadContext, SectionHandle), !UnknownPtr) || !NT_SUCCESS(Status))
	{
		NtClose(SectionHandle);
		NtClose(FileHandle);
		return Status;
	}
	LoadContext->FileHandle = FileHandle;
	LoadContext->SectionHandle = SectionHandle;
	return Status;
}


NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllWithSectionHandle(PLDRP_LOAD_CONTEXT LoadContext, HANDLE SectionHandle) // CHECKED.
{
	NTSTATUS Status;
	NTSTATUS Status2;
	NTSTATUS Status3;
	NTSTATUS Status4;
		
	int v19[14];

	LDR_DATA_TABLE_ENTRY* LdrEntry2;

	// Mapping mechanism.
	Status = fLdrpMinimalMapModule(LoadContext, SectionHandle);
	Status2 = Status;
	if (Status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH)
		return Status2;

	if (!NT_SUCCESS(Status))
		return Status2;

	//LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	SIZE_T Size = LoadContext->Size;
	LDR_DATA_TABLE_ENTRY* LdrEntry = nullptr;
	Status3 = Status;

	PIMAGE_NT_HEADERS OutHeaders;
	Status2 = RtlImageNtHeaderEx(0, DllEntry->DllBase, Size, &OutHeaders);
	if (!NT_SUCCESS(Status2))
		return Status2;

	if (LoadContext->Flags & SEC_FILE)
	{
		Status3 = STATUS_SUCCESS;
		DllEntry->TimeDateStamp = OutHeaders->FileHeader.TimeDateStamp;
		DllEntry->CheckSum = OutHeaders->OptionalHeader.CheckSum;
		DllEntry->SizeOfImage = OutHeaders->OptionalHeader.SizeOfImage;
	}
	else
	{
		RtlAcquireSRWLockExclusive(LdrpModuleDatatableLock);
		UINT_PTR Flags = (LoadContext->Flags) & UINT_MAX;
		PUNICODE_STRING FullDllName_2 = 0;
		if ((Flags & 0x20) == 0)
			FullDllName_2 = &DllEntry->FullDllName;


		// Returns STATUS_DLL_NOT_FOUND is normal situations.
		Status4 = LdrpFindLoadedDllByNameLockHeld(&DllEntry->BaseDllName, FullDllName_2, Flags, &LdrEntry, DllEntry->BaseNameHashValue);
		if (Status4 == STATUS_DLL_NOT_FOUND)
		{
			PIMAGE_DOS_HEADER DllBase = DllEntry->DllBase;
			v19[0] = OutHeaders->FileHeader.TimeDateStamp;
			v19[1] = OutHeaders->OptionalHeader.SizeOfImage;
			LdrpFindLoadedDllByMappingLockHeld(DllBase, OutHeaders, (ULONG*)v19, &LdrEntry);
		}

		if (!LdrEntry)
		{
			LdrpInsertDataTableEntry(DllEntry);
			LdrpInsertModuleToIndexLockHeld(DllEntry, OutHeaders);
		}

		RtlReleaseSRWLockExclusive(LdrpModuleDatatableLock);
		if (LdrEntry)
		{
			if (DllEntry->LoadReason != LoadReasonPatchImage || LdrEntry->LoadReason == LoadReasonPatchImage)
			{
				LdrpLoadContextReplaceModule(LoadContext, LdrEntry);
			}
			else
			{
				Status2 = STATUS_IMAGE_LOADED_AS_PATCH_IMAGE;
				WID_HIDDEN( LdrpLogEtwHotPatchStatus(&(*LdrpImageEntry)->BaseDllName, LoadContext->Entry, &DllEntry->FullDllName, STATUS_IMAGE_LOADED_AS_PATCH_IMAGE, 3); )
				LdrpDereferenceModule(LdrEntry);
			}
			return Status2;
		}
	}
	if (*qword_17E238 == NtCurrentTeb()->ClientId.UniqueThread)
		return STATUS_NOT_FOUND;

	Status2 = fLdrpCompleteMapModule(LoadContext, OutHeaders, Status3);
	if (NT_SUCCESS(Status2))
	{
		Status2 = fLdrpProcessMappedModule(DllEntry, LoadContext->Flags & UINT_MAX, 1);
		if (NT_SUCCESS(Status2))
		{
			WID_HIDDEN( LdrpLogNewDllLoad(LoadContext->Entry, DllEntry); )
			LdrEntry2 = LoadContext->Entry;
			if (LdrEntry2)
				DllEntry->ParentDllBase = LdrEntry2->DllBase;

			BOOLEAN DllBasesEqual = FALSE;
			if (DllEntry->LoadReason == LoadReasonPatchImage && *LdrpImageEntry)
				DllBasesEqual = DllEntry->ParentDllBase == (*LdrpImageEntry)->DllBase;

			if ((LoadContext->Flags & SEC_FILE) || (DllEntry->FlagGroup[0] & ImageDll) || DllBasesEqual)
			{
				if ((DllEntry->Flags & CorILOnly))
				{
					return fLdrpCorProcessImports(DllEntry);
				}
				else
				{
					fLdrpMapAndSnapDependency(LoadContext);
					return *LoadContext->pStatus;
				}
			}
			else
			{
				WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllEntry->DllBase, &DllEntry->FullDllName, 0x14AEu); )
				Status2 = STATUS_SUCCESS;
				DllEntry->DdagNode->State = LdrModulesReadyToRun;
			}
		}
	}

	return Status2;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMinimalMapModule(PLDRP_LOAD_CONTEXT LoadContext, HANDLE SectionHandle)
{
	NTSTATUS Status;

	BOOLEAN UnknownBool;
	int Flags;
	int Flags2;
	ULONG ProtectFlags;
	wchar_t* Buffer;
	MEM_EXTENDED_PARAMETER MemExtendedParam;
	
	void* Data;

	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x2BC, "LdrpMinimalMapModule", 3u, "DLL name: %wZ\n", &DllEntry->FullDllName); )
	if (!RtlEqualUnicodeString(&DllEntry->BaseDllName, LdrpKernel32DllName, TRUE) || (UnknownBool = 1, (*((BYTE*)*LdrpAppHeaders + 0x16) & 0x20) == 0))
	{
		UnknownBool = 0;
	}
	PVOID ReturnedState = nullptr;
	Flags = DontRelocate;
	if (!UnknownBool)
	{
		if (*LdrpLargePageDllKeyHandle)
		{
			Buffer = DllEntry->BaseDllName.Buffer;
			Data = 0;
			RtlQueryImageFileKeyOption(*LdrpLargePageDllKeyHandle, Buffer, 4, &Data, 4, 0);
			if ((DWORD)Data)
			{
				if (NT_SUCCESS(RtlAcquirePrivilege(*LdrpLockMemoryPrivilege, 1, 0, &ReturnedState)))
					Flags = 0x20000000;
			}
		}
	}

	TEB* TEB = NtCurrentTeb();
	LoadContext->Size = 0;
	Data = TEB->NtTib.ArbitraryUserPointer;
	TEB->NtTib.ArbitraryUserPointer = DllEntry->FullDllName.Buffer;

	ULONG64 MaxUsermodeAddress;

	ProtectFlags = (LoadContext->Flags & SEC_LINKER_CREATED) != 0 ? PAGE_READONLY : PAGE_EXECUTE_WRITECOPY;
	Flags2 = Flags | DontCallForThreads;
	if ((LoadContext->Flags & SEC_LINKER_CREATED) == 0)
		Flags2 = Flags;
	if ((LoadContext->Flags & SEC_COFF_SHARED_LIBRARY) != 0)
	{
		MaxUsermodeAddress = *LdrpMaximumUserModeAddress;
		MemExtendedParam.Handle = 0;
		MemExtendedParam.Pointer = &MemExtendedParam.Handle;
		MemExtendedParam.Type = 1;
		Status = ZwMapViewOfSectionEx(SectionHandle, (HANDLE)-1, &DllEntry->DllBase, 0, (PULONG)&LoadContext->Size, Flags2, ProtectFlags, &MemExtendedParam, 1);
	}
	else
	{ 
		// R9 register isn't used by the function (or I couldn't see) but it must be passed anyways so I did.
		// After this function our dll is mapped, DllEntry->DllBase receives the base address.
		Status = fLdrpMapViewOfSection(SectionHandle, ProtectFlags, &DllEntry->DllBase, 0x4B, (PULONG)&LoadContext->Size, Flags2, ProtectFlags, &DllEntry->FullDllName);
	}

	TEB->NtTib.ArbitraryUserPointer = Data;
	if (Flags2 == 0x20000000)
		RtlReleasePrivilege(ReturnedState);

	switch (Status)
	{
	case STATUS_IMAGE_MACHINE_TYPE_MISMATCH:                           
		Status = LdrpProcessMachineMismatch(LoadContext);
		break;
	case STATUS_IMAGE_NOT_AT_BASE:
	case STATUS_IMAGE_AT_DIFFERENT_BASE:
		if (!LoadContext->UnknownPtr && *LdrpMapAndSnapWork)
		{
			if (LdrpCheckForRetryLoading(LoadContext, TRUE))
			{
				Status = STATUS_RETRY;
			}
			else if (UnknownBool)
			{
				Status = STATUS_CONFLICTING_ADDRESSES;
			}
		}
		break;
	}

	if (DllEntry->DllBase && (!NT_SUCCESS(Status) || Status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH))
	{
		NtUnmapViewOfSection((HANDLE)-1, DllEntry->DllBase);
		DllEntry->DllBase = 0;
	}

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x38D, "LdrpMinimalMapModule", 4, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapViewOfSection(HANDLE SectionHandle, ULONG ProtectFlags, PIMAGE_DOS_HEADER* BaseAddress, DWORD Unknown, PULONG ViewSize, ULONG AllocationType, ULONG Win32Protect, PUNICODE_STRING FullDllName)
{
	MEM_EXTENDED_PARAMETER MemExtendedParam; // [rsp+50h] [rbp-18h] BYREF

	// I believe this check is to seperate between Windows dlls and user-made dlls. Goes in if User-made dll.
	if (!LdrpHpatAllocationOptOut(FullDllName))
		return ZwMapViewOfSection(SectionHandle, (HANDLE)-1, BaseAddress, 0, 0, 0, ViewSize, ViewShare, AllocationType, Win32Protect);
	// Windows dlls.
	MemExtendedParam.Type = 5;
	MemExtendedParam.Pointer = (PHANDLE)128;
	return ZwMapViewOfSectionEx(SectionHandle, (HANDLE)-1, BaseAddress, 0, ViewSize, AllocationType, Win32Protect, &MemExtendedParam, 1);
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpCompleteMapModule(PLDRP_LOAD_CONTEXT LoadContext, PIMAGE_NT_HEADERS OutHeaders, NTSTATUS Status)
{
	NTSTATUS ReturnStatus = STATUS_SUCCESS;
	NTSTATUS ReturnStatus2;
	
	//LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	PIMAGE_DOS_HEADER DllBase = DllEntry->DllBase;

	PIMAGE_COR20_HEADER CorHeader = nullptr; 
	ULONG64 LastRVASection = 0;
	ReturnStatus2 = RtlpImageDirectoryEntryToDataEx(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &LastRVASection, &CorHeader);
	if (!NT_SUCCESS(ReturnStatus2))
		CorHeader = 0;

	BOOLEAN JumpIn = FALSE;
	if (!CorHeader)
		JumpIn = TRUE;

	DWORD NewDllFlags = 0;
	if (!JumpIn)
	{
		if ((LoadContext->Flags & SEC_LINKER_CREATED) != 0)
			return STATUS_INVALID_IMAGE_FORMAT;

		NewDllFlags = DllEntry->Flags | CorImage;
		DllEntry->Flags = NewDllFlags;
	}
	if (JumpIn || ((CorHeader->Flags & 1) == 0 || (DllEntry->Flags = NewDllFlags | CorILOnly, ReturnStatus = LdrpCorValidateImage(DllBase), (NT_SUCCESS(ReturnStatus))
		&& ((LoadContext->Flags & SEC_LINK_DUPLICATES_ONE_ONLY) == 0 || (ReturnStatus = LdrpCorFixupImage(DllBase), NT_SUCCESS(ReturnStatus))))))
	{
		if ((OutHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
		{
			if (NT_SUCCESS(*(BYTE*)&(LoadContext->Flags)) || !NT_SUCCESS(*(BYTE*)&(OutHeaders->OptionalHeader.DllCharacteristics)))
			{
				if ((DllEntry->Flags & CorILOnly) == 0 && (Status == STATUS_IMAGE_NOT_AT_BASE || Status == STATUS_IMAGE_AT_DIFFERENT_BASE))
				{
					char* UMGlobalLogger = (char*)&kUserSharedData->UserModeGlobalLogger[2];
					char* UMGlobalLogger_2 = nullptr;
					char* UMGlobalLoggerP1 = nullptr;
					char* UMGlobalLoggerP1_2 = nullptr;

					if (RtlGetCurrentServiceSessionId())
						UMGlobalLogger_2 = (char*)NtCurrentPeb()->SharedData + 0x22A;
					else
						UMGlobalLogger_2 = (char*)&kUserSharedData->UserModeGlobalLogger[2];

					UMGlobalLoggerP1 = (char*)&kUserSharedData->UserModeGlobalLogger[2] + 1;
					if (*(BYTE*)UMGlobalLogger_2 && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
					{
						UMGlobalLoggerP1_2 = RtlGetCurrentServiceSessionId() ? (char*)NtCurrentPeb()->SharedData + 0x22B : (char*)UMGlobalLoggerP1;

						// 0x20 is space char.
						if ((*UMGlobalLoggerP1_2 & ' ') != 0)
							WID_HIDDEN( LdrpLogEtwEvent(0x1490u, (ULONGLONG)DllBase, 0xFFu, 0xFFu); )
					}

					if (Status == STATUS_IMAGE_NOT_AT_BASE && (ReturnStatus = fLdrpRelocateImage(DllEntry->DllBase, LoadContext->Size, OutHeaders, &DllEntry->FullDllName), !NT_SUCCESS(ReturnStatus)))
					{
						WID_HIDDEN( LdrpLogError(ReturnStatus, 0x1490u, 0, &DllEntry->FullDllName); )
					}
					else
					{
						if (RtlGetCurrentServiceSessionId())
							UMGlobalLogger = (char*)NtCurrentPeb()->SharedData + 0x22A;

						if (*(BYTE*)UMGlobalLogger && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
						{
							if (RtlGetCurrentServiceSessionId())
								UMGlobalLoggerP1 = (char*)NtCurrentPeb()->SharedData + 0x22B;

							// 0x20 is space char.
							if ((*(BYTE*)UMGlobalLoggerP1 & ' ') != 0)
								WID_HIDDEN( LdrpLogEtwEvent(0x1491u, (ULONGLONG)DllBase, 0xFFu, 0xFFu); )
						}
					}
				}
			}
			else
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 1009, "LdrpCompleteMapModule", 0, "Could not validate the crypto signature for DLL %wZ\n", &DllEntry->FullDllName); )
				return STATUS_INVALID_IMAGE_HASH;
			}
		}
		else
		{
			DllEntry->Flags &= ~ImageDll;
		}
	}
	return ReturnStatus;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpRelocateImage(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeaders, PUNICODE_STRING FullDllName)
{
	NTSTATUS Status;
	
	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x164, "LdrpRelocateImage", 3, "DLL name: %wZ\n", FullDllName); )

	Status = STATUS_SUCCESS;

	// To delete goto.
	BOOLEAN PassOver = FALSE;
	if ((OutHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0)
		PassOver = TRUE;

	UINT_PTR LastRVASection;
	PIMAGE_BASE_RELOCATION BaseReloc;
	if (!PassOver)
	{
		Status = RtlpImageDirectoryEntryToDataEx(DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &LastRVASection, (PVOID*)&BaseReloc);
		if (!NT_SUCCESS(Status))
			BaseReloc = 0;
	}
	if (PassOver || (BaseReloc && (DWORD)LastRVASection))
	{
		if (!LdrpIsILOnlyImage(DllBase))
		{
			WID_HIDDEN( LdrpLogDllRelocationEtwEvent(FullDllName, OutHeaders->OptionalHeader.ImageBase, DllBase, Size); )
			Status = fLdrpProtectAndRelocateImage(DllBase, Size, OutHeaders);
		}
	}

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 396, "LdrpRelocateImage", 4u, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpProtectAndRelocateImage(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeader)
{
	NTSTATUS Status;

	do
	{
		BOOLEAN DoNotRelocate = FALSE;

		// The DOS header receives memory information.
		MEMORY_WORKING_SET_EX_INFORMATION MemoryWorkingSetExInfo;
		MemoryWorkingSetExInfo.VirtualAddress = DllBase;
		Status = ZwQueryVirtualMemory((HANDLE)-1, 0, MemoryWorkingSetExInformation, &MemoryWorkingSetExInfo, 0x10, 0);
		if (!NT_SUCCESS(Status))
		{
			WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x7BC, "LdrpProtectAndRelocateImage", 0, "Querying large page info failed with status 0x%08lx\n", Status); )
		}
		else if ((MemoryWorkingSetExInfo.u1.Long & PackagedBinary) != 0)
		{
			DoNotRelocate = (MemoryWorkingSetExInfo.u1.Long & DontRelocate) != 0;
		}

		if (!DontRelocate)
		{
			Status = fLdrpSetProtection(DllBase, FALSE);
			if (!NT_SUCCESS(Status))
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x7C6, "LdrpProtectAndRelocateImage", 0, "Changing the protection of the executable at %p failed with status 0x%08lx\n", DllBase, Status); )
				break;
			}
		}

		Status = fLdrRelocateImageWithBias(DllBase, Size, OutHeader);
		if (NT_SUCCESS(Status) && !DontRelocate)
		{
			Status = fLdrpSetProtection(DllBase, TRUE);
			if (!NT_SUCCESS(Status))
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x7DE, "LdrpProtectAndRelocateImage", 0, "Changing the protection of the executable at %p failed with status 0x%08lx\n", DllBase, Status); )
				break;
			}
		}
	} while (FALSE);

	WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x806, "LdrpProtectAndRelocateImage", 4u, "Status: 0x%08lx\n", Status); )
	return Status;
}

NTSTATUS __fastcall	LOADLIBRARY::fLdrpSetProtection(PIMAGE_DOS_HEADER DllBase, BOOLEAN Unknown)
{
	NTSTATUS Status;

	PIMAGE_NT_HEADERS NtHeader;
	RtlImageNtHeaderEx(3, DllBase, 0, &NtHeader);
	PIMAGE_NT_HEADERS NtHeader_2 = NtHeader;
	
	if (!NtHeader->FileHeader.NumberOfSections)
		return STATUS_SUCCESS;

	LONG SectionIdx = 0;
	for (PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((char*)&NtHeader->OptionalHeader.AddressOfEntryPoint + NtHeader->FileHeader.SizeOfOptionalHeader); ; ++SectionHeader)
	{
		LONG pRawData = SectionHeader->PointerToRawData;
		if (pRawData >= 0 && *(DWORD*)SectionHeader->Name)
		{
			ULONG Flags;
			ULONG Flags2;
			if (Unknown)
			{
				// Reserved (0x2), Reserved (0x10)
				Flags = (pRawData & IMAGE_SCN_MEM_EXECUTE) != 0 ? ((pRawData & IMAGE_SCN_MEM_READ) != 0 ? IMAGE_SCN_CNT_CODE : 0x10) : 2;
				Flags2 = Flags | IMAGE_SCN_LNK_INFO;
				if ((pRawData & IMAGE_SCN_MEM_NOT_CACHED) == 0)
					Flags2 = Flags;
			}
			else
			{
				// Reserved (0x4)
				Flags2 = 4;
			}
			PVOID BaseAddress[6];
			BaseAddress[0] = (char*)DllBase + SectionHeader[-1].Characteristics;
			ULONG64 NumberOfBytesToProtect = *(unsigned int*)SectionHeader->Name;
			if (NumberOfBytesToProtect)
			{
				ULONG OldAccessProtection;
				Status = ZwProtectVirtualMemory((HANDLE)-1, BaseAddress, (PULONG)&NumberOfBytesToProtect, Flags2, &OldAccessProtection);
				if (!NT_SUCCESS(Status))
					break;
			}
		}
		if (++SectionIdx >= (unsigned int)NtHeader_2->FileHeader.NumberOfSections)
			return STATUS_SUCCESS;
	}
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrRelocateImageWithBias(PIMAGE_DOS_HEADER DllBase, SIZE_T Size, PIMAGE_NT_HEADERS OutHeader)
{
	NTSTATUS Status = STATUS_SUCCESS;
	
	PIMAGE_NT_HEADERS NtHeader_4;
	ULONG64 ImageBaseHigh;
	NTSTATUS Status_2;
	PIMAGE_NT_HEADERS NtHeader_3;
	ULONG LastRVASection_2;
	ULONG Machine;
	PIMAGE_NT_HEADERS NtHeader_2;

	NtHeader_2 = OutHeader;
	ULONG64 LastRVASection = 0;
	if (!NT_SUCCESS(RtlImageNtHeaderEx(1, DllBase, 0, &NtHeader_2)))
		return STATUS_INVALID_IMAGE_FORMAT;
	NtHeader_4 = NtHeader_2;
	if (NtHeader_2->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		ImageBaseHigh = (NtHeader_2->OptionalHeader.ImageBase) & 0xFFFFFFFF00000000;
	}
	else
	{
		if (NtHeader_2->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return STATUS_INVALID_IMAGE_FORMAT;
		ImageBaseHigh = NtHeader_2->OptionalHeader.ImageBase;
	}

	Status_2 = RtlpImageDirectoryEntryToDataEx(DllBase, 1u, IMAGE_DIRECTORY_ENTRY_BASERELOC, &LastRVASection, (PVOID*)&NtHeader_2);
	NtHeader_3 = NtHeader_2;
	if (!NT_SUCCESS(Status_2))
		NtHeader_3 = 0;

	if (!NtHeader_3)
		return (NtHeader_4->FileHeader.Characteristics & 1) != 0 ? STATUS_CONFLICTING_ADDRESSES : 0;

	LastRVASection_2 = LastRVASection;
	if (!(DWORD)LastRVASection)
		return (NtHeader_4->FileHeader.Characteristics & 1) != 0 ? STATUS_CONFLICTING_ADDRESSES : 0;

	while (TRUE)
	{
		Machine = *(DWORD*)&NtHeader_3->FileHeader.Machine;
		LastRVASection_2 -= Machine;
		NtHeader_3 = fLdrProcessRelocationBlockLongLong(NtHeader_4->FileHeader.Machine, (LONG)DllBase + NtHeader_3->Signature, (ULONG)(Machine - 8) >> 1, (PIMAGE_NT_HEADERS64)((LONG)NtHeader_3 + 8), (UINT_PTR)DllBase - ImageBaseHigh);
		if (!NtHeader_3)
			break;

		if (!LastRVASection_2)
			return Status;
	}
	return STATUS_INVALID_IMAGE_FORMAT;
}

PIMAGE_NT_HEADERS __fastcall LOADLIBRARY::fLdrProcessRelocationBlockLongLong(USHORT Machine, ULONG64 Signature, ULONG64 Unknown, PIMAGE_NT_HEADERS64 NtHeader, ULONG64 Unknown2)
{
	// TO DO.

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpProcessMappedModule(PLDR_DATA_TABLE_ENTRY DllEntry, UINT_PTR Flags, ULONG One)
{
	NTSTATUS Status;	

	PIMAGE_DOS_HEADER DllBase = DllEntry->DllBase;

	PIMAGE_NT_HEADERS OutHeaders;
	Status = RtlImageNtHeaderEx(3, DllBase, 0, &OutHeaders);
	if (!NT_SUCCESS(Status))
		return Status;

	PIMAGE_NT_HEADERS OutHeaders_2 = OutHeaders;

	if ((DllEntry->Flags & (ImageDll | CorILOnly)) == ImageDll && DllEntry->LoadReason != LoadReasonPatchImage)
	{
		PLDR_INIT_ROUTINE EntryPoint = nullptr;
		if (OutHeaders->OptionalHeader.AddressOfEntryPoint)
			EntryPoint = (PLDR_INIT_ROUTINE)((char*)DllBase + OutHeaders->OptionalHeader.AddressOfEntryPoint);
		else
			EntryPoint = nullptr;

		DllEntry->EntryPoint = EntryPoint;
	}

	if (!LdrpValidateEntrySection(DllEntry))
		return STATUS_INVALID_IMAGE_FORMAT;

	DllEntry->OriginalBase = OutHeaders_2->OptionalHeader.ImageBase;
	DllEntry->LoadTime.QuadPart = *(LONGLONG*)(0x7FFE0014);
	do
	{
		if ((Flags & 0x800000) == 0 && ((DllEntry->FlagGroup[0] & 4) != 0 || One && LdrpIsExecutableRelocatedImage(DllBase)) && (DllEntry->Flags & LoadConfigProcessed) == 0 && One)
		{
			UINT_PTR Zero = 0;
			UINT_PTR RandomNumber = LdrpGenRandom();
			BOOL IsInited = LdrInitSecurityCookie(DllBase, DllEntry->SizeOfImage, 0, RandomNumber ^ *dword_199398, &Zero);
			if (!DllBase || !DllEntry->EntryPoint || (OutHeaders->OptionalHeader.MajorSubsystemVersion != 6 || OutHeaders->OptionalHeader.MinorSubsystemVersion < IMAGE_SUBSYSTEM_WINDOWS_CUI) && OutHeaders->OptionalHeader.MajorSubsystemVersion < IMAGE_SUBSYSTEM_POSIX_CUI || IsInited)
			{
				Status = LdrpCfgProcessLoadConfig(DllEntry, OutHeaders, Zero);
				if (!NT_SUCCESS(Status))
					return Status;
				break;
			}
			return STATUS_INVALID_IMAGE_FORMAT;
		}
	} while (FALSE);

	if ((Flags & 0x800000) == 0 && (DllEntry->Flags & InExceptionTable) == 0)
		RtlInsertInvertedFunctionTable(DllBase, DllEntry->SizeOfImage);

	DllEntry->Flags |= InExceptionTable | LoadConfigProcessed;
	RtlAcquireSRWLockExclusive(LdrpModuleDatatableLock);
	DllEntry->DdagNode->State = LdrModulesMapped;
	if ((Flags & 0x800000) == 0 && DllEntry->LoadContext)
		LdrpSignalModuleMapped(DllEntry);

	RtlReleaseSRWLockExclusive(LdrpModuleDatatableLock);
	
	WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllEntry->DllBase, &DllEntry->FullDllName, 0x14A1u); )
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpCorProcessImports(PLDR_DATA_TABLE_ENTRY DllEntry)
{
	NTSTATUS Status = STATUS_SUCCESS; 

	DllEntry->DdagNode->State = LdrModulesCondensed;
	Status = AVrfDllLoadNotification(DllEntry);
	if (NT_SUCCESS(Status))
	{
		LdrpSendDllNotifications(DllEntry, 1);
		WID_HIDDEN( LdrpLogDllState((UINT_PTR)DllEntry->DllBase, &DllEntry->FullDllName, 0x14ADu); )
		DllEntry->DdagNode->State = LdrModulesReadyToInit;
	}
	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpMapAndSnapDependency(PLDRP_LOAD_CONTEXT LoadContext)
{
	NTSTATUS Status;
		
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	BOOLEAN IsFile = (LoadContext->Flags & SEC_FILE);
	BOOLEAN FullPathExists = 0;

	UNICODE_STRING FullPath;
	memset(&FullPath, 0, sizeof(FullPath));

	do
	{
		if (!IsFile)
		{
			if (DllEntry->LoadReason != LoadReasonPatchImage)
			{
				Status = LdrpFindDllActivationContext(DllEntry);
				if (!NT_SUCCESS(Status))
					break;
			}
		}

		Status = fLdrpPrepareImportAddressTableForSnap(LoadContext);
		if (!NT_SUCCESS(Status))
			break;

		ULONG CurrentDllDecremented = 0;
		ULONG OldCurrentDll = 0;
		if (*LdrpIsHotPatchingEnabled)
		{
			DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (DllEntry)
			{
				Status = LdrpQueryCurrentPatch(DllEntry->CheckSum, DllEntry->TimeDateStamp, &FullPath);
				if (!NT_SUCCESS(Status))
					break;

				if (FullPath.Length)
					FullPathExists = TRUE;
			}
		}

		PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = nullptr;
		if (LoadContext->pImageImportDescriptor || FullPathExists)
		{
			if (LdrpShouldModuleImportBeRedirected(DllEntry))
				LoadContext->Flags |= 0x2000000u;

			ImageImportDescriptor = LdrpGetImportDescriptorForSnap(LoadContext);
			ULONG IATSize = 0;
			PIMAGE_THUNK_DATA32 FirstThunk = (PIMAGE_THUNK_DATA32)&ImageImportDescriptor->FirstThunk;

			BOOLEAN JumpIn = FALSE;
			if (ImageImportDescriptor)
			{
				PIMAGE_THUNK_DATA32 FirstThunk2 = (IMAGE_THUNK_DATA32*)&ImageImportDescriptor->FirstThunk;
				ULONG DllBaseIncremented = 0;
				do
				{
					if (!FirstThunk2[-1].u1.ForwarderString)
						break;

					ULONG ForwarderString = FirstThunk2->u1.ForwarderString;
					if (!FirstThunk2->u1.ForwarderString)
						break;

					ULONG DllBaseIncremented_2 = DllBaseIncremented + 1;
					FirstThunk2 += 5;
					++IATSize;
					if (!*(UINT_PTR*)((char*)&DllEntry->DllBase->e_magic + ForwarderString))
						DllBaseIncremented_2 = DllBaseIncremented;

					DllBaseIncremented = DllBaseIncremented_2;
				} while (FirstThunk2 != (IMAGE_THUNK_DATA32*)16);

				OldCurrentDll = DllBaseIncremented;
				if (DllBaseIncremented)
					JumpIn = TRUE;
			}

			BOOLEAN JumpOut = FALSE;
			if (JumpIn || FullPathExists)
			{
				PVOID* Heap = (PVOID*)RtlAllocateHeap(*LdrpHeap, (*NtdllBaseTag + 0x180000) | 8u, 8 * IATSize);
				LoadContext->IATCheck = (LDR_DATA_TABLE_ENTRY**)Heap;
				if (Heap)
				{
					LoadContext->SizeOfIAT = IATSize;
					LoadContext->GuardCFCheckFunctionPointer = ImageImportDescriptor;
					LoadContext->CurrentDll = OldCurrentDll + 1;
					if (FullPathExists)
						LoadContext->CurrentDll = OldCurrentDll + 2;

					PIMAGE_THUNK_DATA pThunk = nullptr;
					UINT_PTR IATAmount = 0;
					if (ImageImportDescriptor)
					{
						while (FirstThunk[-1].u1.ForwarderString && FirstThunk->u1.ForwarderString)
						{
							PIMAGE_DOS_HEADER DllBase = DllEntry->DllBase;
							if (*(UINT_PTR*)((char*)&DllBase->e_magic + FirstThunk->u1.ForwarderString))
							{
								ULONG ForwarderString_2 = FirstThunk[-1].u1.ForwarderString;
								IsFile = (PIMAGE_IMPORT_BY_NAME)(ForwarderString_2 + (UINT_PTR)DllBase) != 0;
								PCHAR ForwarderBuffer = (PCHAR)(ForwarderString_2 + (UINT_PTR)DllBase);

								STRING SourceString = {};
								*(UINT_PTR*)&SourceString.Length = 0;
								SourceString.Buffer = ForwarderBuffer;
								if (IsFile)
								{
									SIZE_T SourceLen = -1;
									do
									{
										++SourceLen;
									} while (ForwarderBuffer[SourceLen]);

									if (SourceLen > 0xFFFE)
									{
										Status = STATUS_NAME_TOO_LONG;
										break;
									}

									SourceString.Length = SourceLen;
									SourceString.MaximumLength = SourceLen + 1;
								}

								Status = LdrpLoadDependentModuleA((PUNICODE_STRING)&SourceString, LoadContext, DllEntry, 0, &LoadContext->IATCheck[IATAmount], (UINT_PTR)&pThunk);
								if (!NT_SUCCESS(Status))
									break;
							}

							FirstThunk += 5;
							IATAmount = (ULONG)(IATAmount + 1);
							if (FirstThunk == (PIMAGE_THUNK_DATA32)16)
								break;
						}
					}
					if (FullPathExists)
					{
						// Loads Imports dlls.
						Status = LdrpLoadDependentModuleW(&FullPath, LoadContext, DllEntry);
						if (!NT_SUCCESS(Status))
							WID_HIDDEN(LdrpLogEtwHotPatchStatus(&(*LdrpImageEntry)->BaseDllName, DllEntry, &FullPath, Status, 5u); )
					}

					if (pThunk)
						RtlFreeHeap(*LdrpHeap, 0, pThunk);

					if (NT_SUCCESS(Status))
					{
						RtlAcquireSRWLockExclusive(LdrpModuleDatatableLock);
						CurrentDllDecremented = --LoadContext->CurrentDll;
						RtlReleaseSRWLockExclusive(LdrpModuleDatatableLock);
						JumpOut = TRUE;
					}
				}
				else
				{
					Status = STATUS_NO_MEMORY;
				}
			}

			if (!JumpOut)
				CurrentDllDecremented = OldCurrentDll;
		}

		PLDR_DDAG_NODE DdagNode = nullptr;
		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = LoadContext->pImageImportDescriptor;
		if (pImageImportDescriptor || !FullPathExists)
		{
			if (CurrentDllDecremented)
				break;

			DdagNode = DllEntry->DdagNode;
			if (pImageImportDescriptor)
			{
				DdagNode->State = LdrModulesSnapping;
				if (LoadContext->Entry)
					LdrpQueueWork(LoadContext);
				else
					Status = fLdrpSnapModule(LoadContext);
				break;
			}
		}
		else
		{
			DdagNode = DllEntry->DdagNode;
		}

		DdagNode->State = LdrModulesSnapped;
	} while (FALSE);

	LdrpFreeUnicodeString(&FullPath);
	if (!NT_SUCCESS(Status))
	{
		*LoadContext->pStatus = Status;
	}

	return *LoadContext->pStatus;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpPrepareImportAddressTableForSnap(LDRP_LOAD_CONTEXT* LoadContext)
{
	NTSTATUS Status;
	
	LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = nullptr;
	UINT_PTR* pImageImportDescriptorLen = (UINT_PTR*)&LoadContext->ImageImportDescriptorLen;
	Status = RtlpImageDirectoryEntryToDataEx(DllEntry->DllBase, 1u, IMAGE_DIRECTORY_ENTRY_IAT, (UINT_PTR*)&LoadContext->ImageImportDescriptorLen, &ImageImportDescriptor);
	if (!NT_SUCCESS(Status))
		ImageImportDescriptor = nullptr;

	BOOLEAN IsFile = (LoadContext->Flags & SEC_FILE);
	LoadContext->pImageImportDescriptor = ImageImportDescriptor;
	if (IsFile)
		return STATUS_SUCCESS;

	BOOLEAN JumpOver = FALSE;

	PIMAGE_NT_HEADERS OutHeaders = nullptr;
	RtlImageNtHeaderEx(3, DllEntry->DllBase, 0, &OutHeaders);
	PIMAGE_LOAD_CONFIG_DIRECTORY ImageConfigDirectory = LdrImageDirectoryEntryToLoadConfig(DllEntry->DllBase);
	if (!ImageConfigDirectory || ImageConfigDirectory->Size < 0x94)
		JumpOver = TRUE;

	if (!JumpOver)
	{
		if ((OutHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0 && (ImageConfigDirectory->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0)
		{
			UINT_PTR* GuardCFCheckFunctionPointer = (UINT_PTR*)ImageConfigDirectory->GuardCFCheckFunctionPointer;
			LoadContext->UnknownFunc = (__int64)GuardCFCheckFunctionPointer;
			if (GuardCFCheckFunctionPointer)
			{
				LoadContext->DllNameLenCompare = *GuardCFCheckFunctionPointer;
			}
		}
	}

	do
	{
		if (!LoadContext->pImageImportDescriptor)
		{
			ULONG ImportDirectoryVA = OutHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			PIMAGE_SECTION_HEADER FirstSection = (PIMAGE_SECTION_HEADER)((char*)&OutHeaders->OptionalHeader + OutHeaders->FileHeader.SizeOfOptionalHeader);
			if (ImportDirectoryVA)
			{
				ULONG SectionIdx = 0;
				if (OutHeaders->FileHeader.NumberOfSections)
				{
					ULONG SectionVA = 0;
					while (TRUE)
					{
						SectionVA = FirstSection->VirtualAddress;
						if (ImportDirectoryVA >= SectionVA && ImportDirectoryVA < SectionVA + FirstSection->SizeOfRawData)
							break;

						++SectionIdx;
						++FirstSection;

						if (SectionIdx >= OutHeaders->FileHeader.NumberOfSections)
							break;
					}

					LoadContext->pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char*)DllEntry->DllBase + SectionVA);
					ULONG SectionFA = FirstSection->Misc.PhysicalAddress;
					*pImageImportDescriptorLen = SectionFA;
					if (!SectionFA)
						*pImageImportDescriptorLen = FirstSection->SizeOfRawData;
				}
			}
		}
	} while (FALSE);

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = LoadContext->pImageImportDescriptor;
	if (pImageImportDescriptor && *pImageImportDescriptorLen)
	{
		UINT_PTR ImageImportDescriptorLen = *pImageImportDescriptorLen;

		NTSTATUS Status_2 = ZwProtectVirtualMemory((HANDLE)-1, (PVOID*)&pImageImportDescriptor, (PULONG)&ImageImportDescriptorLen, PAGE_READWRITE, (PULONG)&LoadContext->GuardFlags);
		if (!NT_SUCCESS(Status_2))
			return Status_2;

		PIMAGE_IMPORT_DESCRIPTOR pNextSectionMaybe = pImageImportDescriptor;
		PIMAGE_IMPORT_DESCRIPTOR pNextImageImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((char*)pImageImportDescriptor + ImageImportDescriptorLen);
		do
		{
			pNextSectionMaybe = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pNextSectionMaybe + 0x1000);
		} while (pNextSectionMaybe < pNextImageImportDescriptor);
	}
	return STATUS_SUCCESS;
}



NTSTATUS __fastcall LOADLIBRARY::fLdrpPrepareModuleForExecution(PLDR_DATA_TABLE_ENTRY LdrEntry, NTSTATUS* pStatus)
{
	NTSTATUS Status;

	Status = STATUS_SUCCESS;
	if (*qword_17E238 == NtCurrentTeb()->ClientId.UniqueThread)
		return Status;

	BOOLEAN Skip = FALSE;

	LDR_DDAG_NODE* DdagNode = LdrEntry->DdagNode;
	switch (DdagNode->State)
	{
	case LdrModulesSnapped:
		LdrpCondenseGraph(DdagNode);
	case LdrModulesCondensed:
	{
		// This is where we'll start from normally.
		if ((LdrEntry->FlagGroup[0] & ProcessStaticImport) == 0)
		{
			UINT_PTR SubProcessTag = (UINT_PTR)NtCurrentTeb()->SubProcessTag;
			LdrpAddNodeServiceTag(DdagNode, SubProcessTag);
		}

		Status = LdrpNotifyLoadOfGraph(DdagNode);
		if (NT_SUCCESS(Status))
		{
			Status = LdrpDynamicShimModule(DdagNode);
			if (!NT_SUCCESS(Status))
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 0x9F3, "LdrpPrepareModuleForExecution", 1u, "Failed to load for appcompat reasons\n"); )
				return Status;
			}
			Skip = TRUE;
		}

		if (!Skip)
			return Status;
	}
	case LdrModulesReadyToInit:
		LDRP_LOAD_CONTEXT* LoadContext = (LDRP_LOAD_CONTEXT*)LdrEntry->LoadContext;
		if (LoadContext && (LoadContext->Flags & 1) == 0)
		{
			LdrpAcquireLoaderLock();

			UINT64 Unknown = 0;
			Status = fLdrpInitializeGraphRecurse(DdagNode, pStatus, (char*)&Unknown);

			ULONG64 Unused = 0;
			LdrpReleaseLoaderLock(Unused, 2, Status);
		}
		return Status;
	}

	// States end at 9.
	if (DdagNode->State > LdrModulesReadyToRun)
		return STATUS_INTERNAL_ERROR;

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpInitializeGraphRecurse(LDR_DDAG_NODE* DdagNode, NTSTATUS* pStatus, char* Unknown)
{
	NTSTATUS Status = STATUS_SUCCESS;

	if (DdagNode->State == LdrModulesInitError)
		return STATUS_DLL_INIT_FAILED;

	LDR_DDAG_NODE* DdagNode2 = (LDR_DDAG_NODE*)DdagNode->Dependencies.Tail;
	CHAR Unknown2_2 = 0;
	CHAR Unknown2 = 0;

	BOOLEAN JumpIn = FALSE;
	do
	{
		if (DdagNode2)
		{
			LDR_DDAG_NODE* DdagNode2_2 = DdagNode2;
			do
			{
				DdagNode2_2 = (LDR_DDAG_NODE*)DdagNode2_2->Modules.Flink;
				if ((DdagNode2_2->LoadCount & 1) == 0)
				{
					LDR_DDAG_NODE* Blink = (LDR_DDAG_NODE*)DdagNode2_2->Modules.Blink;
					if (Blink->State == LdrModulesReadyToInit)
					{
						Status = fLdrpInitializeGraphRecurse(Blink, pStatus, &Unknown2);
						if (!NT_SUCCESS(Status))
						{
							JumpIn = TRUE;
							break;
						}
						Unknown2_2 = Unknown2;
					}
					else
					{
						if (Blink->State == LdrModulesInitError)
						{
							Status = STATUS_DLL_INIT_FAILED;
							{
								JumpIn = TRUE;
								break;
							}
						}
						if (Blink->State == LdrModulesInitializing)
							Unknown2_2 = 1;
						Unknown2 = Unknown2_2;
					}
				}
			} while (DdagNode2_2 != DdagNode2);

			if (JumpIn)
				break;

			if (Unknown2_2)
			{
				LDR_DDAG_NODE* DdagNode3 = (LDR_DDAG_NODE*)DdagNode->Modules.Flink;
				*Unknown = 1;
				LDR_SERVICE_TAG_RECORD* ServiceTagList = DdagNode3->ServiceTagList;
				if (ServiceTagList)
				{
					if (pStatus != *(NTSTATUS**)&ServiceTagList[2].ServiceTag)
						return STATUS_SUCCESS;
				}
			}
		}
	} while (FALSE);

	if (!JumpIn)
		Status = fLdrpInitializeNode(DdagNode);

	if (JumpIn || !NT_SUCCESS(Status))
		DdagNode->State = LdrModulesInitError;

	return Status;
}

NTSTATUS __fastcall LOADLIBRARY::fLdrpInitializeNode(LDR_DDAG_NODE* DdagNode)
{
	NTSTATUS Status;
	NTSTATUS Status_2;
	NTSTATUS Status_3;

	LDR_DDAG_STATE* pState = &DdagNode->State;

	UNICODE_STRING FullDllName;
	*(UINT_PTR*)&FullDllName.Length = (UINT_PTR)&DdagNode->State;
	DdagNode->State = LdrModulesInitializing;

	LDR_DATA_TABLE_ENTRY* Blink = (LDR_DATA_TABLE_ENTRY*)DdagNode->Modules.Blink;
	LDR_DATA_TABLE_ENTRY* LdrEntry = *LdrpImageEntry;
	UINT_PTR** v4 = (UINT_PTR**)*qword_1843B8;
	while (Blink != (LDR_DATA_TABLE_ENTRY*)DdagNode)
	{
		if (&Blink[-1].DdagNode != (LDR_DDAG_NODE**)LdrEntry)
		{
			PVOID* p_ParentDllBase = &Blink[-1].ParentDllBase;
			if (*v4 != qword_1843B0)
				__fastfail(3u);

			*p_ParentDllBase = qword_1843B0;
			Blink[-1].SwitchBackContext = v4;
			*v4 = (UINT_PTR*)p_ParentDllBase;
			v4 = (UINT_PTR**)&Blink[-1].ParentDllBase;
			*qword_1843B8 = (UINT_PTR**)v4;
		}

		Blink = (LDR_DATA_TABLE_ENTRY*)Blink->InLoadOrderLinks.Blink;
	}

	Status = STATUS_SUCCESS;
	for (LDR_DATA_TABLE_ENTRY* i = (LDR_DATA_TABLE_ENTRY*)DdagNode->Modules.Blink; i != (LDR_DATA_TABLE_ENTRY*)DdagNode; i = (LDR_DATA_TABLE_ENTRY*)i->InLoadOrderLinks.Blink)
	{
		LDR_DATA_TABLE_ENTRY* LdrEntry_2 = (LDR_DATA_TABLE_ENTRY*)((char*)i - 160);
		if (&i[-1].DdagNode != (LDR_DDAG_NODE**)LdrEntry)
		{
			if (LdrEntry_2->LoadReason == LoadReasonPatchImage)
			{
				Status_2 = LdrpApplyPatchImage((PLDR_DATA_TABLE_ENTRY)&i[-1].DdagNode);
				Status = Status_2;
				if (!NT_SUCCESS(Status_2))
				{
					FullDllName = LdrEntry_2->FullDllName;
					Status_3 = Status_2;
					WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 1392, "LdrpInitializeNode", 0, "Applying patch \"%wZ\" failed - Status = 0x%x\n", &FullDllName, *(UINT_PTR*)&Status_3); )
					break;
				}
			}

			UINT_PTR CurrentDllIniter = *LdrpCurrentDllInitializer;
			*LdrpCurrentDllInitializer = (UINT_PTR)&i[-1].DdagNode;
			PVOID EntryPoint = LdrEntry_2->EntryPoint;
			PUNICODE_STRING pFullDllName = &LdrEntry_2->FullDllName;
			WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 1411, "LdrpInitializeNode", 2u, "Calling init routine %p for DLL \"%wZ\"\n", EntryPoint, &LdrEntry_2->FullDllName); )
			
			RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED StackFrameExtended;
			StackFrameExtended.Size = 0x48;
			StackFrameExtended.Format = 1;
			memset((char*)&StackFrameExtended.Frame.Previous + 4, 0, 48);
			UINT_PTR v20 = 0;
			RtlActivateActivationContextUnsafeFast(&StackFrameExtended, LdrEntry_2->EntryPointActivationContext);
			if (LdrEntry_2->TlsIndex)
				fLdrpCallTlsInitializers(1i64, (LDR_DATA_TABLE_ENTRY*)&i[-1].DdagNode);

			BOOLEAN CallSuccess = TRUE;
			if (EntryPoint)
			{
				LPVOID ContextRecord = nullptr;
				if ((LdrEntry_2->FlagGroup[0] & ProcessStaticImport) != 0)
					ContextRecord = *LdrpProcessInitContextRecord;

				CallSuccess = fLdrpCallInitRoutine((BOOL(__stdcall*)(HINSTANCE, DWORD, LPVOID))EntryPoint, LdrEntry_2->DllBase, DLL_PROCESS_ATTACH, ContextRecord);
			}

			RtlDeactivateActivationContextUnsafeFast(&StackFrameExtended);
			*LdrpCurrentDllInitializer = CurrentDllIniter;
			LdrEntry_2->Flags |= ProcessAttachCalled;
			if (!CallSuccess)
			{
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 0x5B7, "LdrpInitializeNode", 0, "Init routine %p for DLL \"%wZ\" failed during DLL_PROCESS_ATTACH\n", EntryPoint, pFullDllName); )
				Status = STATUS_DLL_INIT_FAILED;
				LdrEntry_2->Flags |= ProcessAttachFailed;
				break;
			}

			WID_HIDDEN( LdrpLogDllState((UINT_PTR)LdrEntry_2->DllBase, pFullDllName, 0x14AEu); )
			LdrEntry = *LdrpImageEntry;
		}
	}
	*pState = Status != 0 ? LdrModulesInitError : LdrModulesReadyToRun;
	return Status;
}

BOOL __fastcall LOADLIBRARY::fLdrpCallTlsInitializers(DWORD fdwReason, LDR_DATA_TABLE_ENTRY* LdrEntry)
{
	BOOL Result = FALSE;

	RtlAcquireSRWLockShared(LdrpTlsLock);

	TLS_ENTRY* TlsEntry = LdrpFindTlsEntry(LdrEntry);

	RtlReleaseSRWLockShared(LdrpTlsLock);
	if (TlsEntry)
	{
		LPVOID* AddressOfCallBacks = (LPVOID*)TlsEntry->TlsDirectory.AddressOfCallBacks;
		if (AddressOfCallBacks)
		{
			while (TRUE)
			{
				LPVOID ContextRecord = *AddressOfCallBacks;
				if (!ContextRecord)
					break;

				++AddressOfCallBacks;
				WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrtls.c", 1180, "LdrpCallTlsInitializers", 2u, "Calling TLS callback %p for DLL \"%wZ\" at %p\n", ContextRecord, &LdrEntry->FullDllName, LdrEntry->DllBase); )
				
				Result = fLdrpCallInitRoutine(ImageTlsCallbackCaller, LdrEntry->DllBase, fdwReason, ContextRecord);
			}
		}
	}

	return Result;
}

BOOLEAN __fastcall LOADLIBRARY::fLdrpCallInitRoutine(BOOL(__fastcall* DllMain)(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved), PIMAGE_DOS_HEADER DllBase, unsigned int One, LPVOID ContextRecord)
{
	BOOLEAN ReturnVal = TRUE;

	PCHAR LoggingVar = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2];
	PCHAR LoggingVar2 = 0;
	if (RtlGetCurrentServiceSessionId())
		LoggingVar2 = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253];
	else
		LoggingVar2 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2];

	PCHAR LoggingVar3 = 0;
	PCHAR LoggingVar4 = 0;
	if (*LoggingVar2 && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
	{
		LoggingVar3 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
		if (RtlGetCurrentServiceSessionId())
			LoggingVar4 = (char*)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1;
		else
			LoggingVar4 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;

		// 0x20 is SPACE char.
		if ((*LoggingVar4 & ' ') != 0)
			WID_HIDDEN( LdrpLogEtwEvent(0x14A3u, (ULONGLONG)DllBase, 0xFF, 0xFF); )
	}
	else
	{
		LoggingVar3 = (PCHAR)&kUserSharedData->UserModeGlobalLogger[2] + 1;
	}

	// DLL_PROCESS_ATTACH (1)
	ReturnVal = DllMain((HINSTANCE)DllBase, One, ContextRecord);
	if (RtlGetCurrentServiceSessionId())
		LoggingVar = (PCHAR)&NtCurrentPeb()->SharedData->NtSystemRoot[253];

	if (*LoggingVar && (NtCurrentPeb()->TracingFlags & LibLoaderTracingEnabled) != 0)
	{
		if (RtlGetCurrentServiceSessionId())
			LoggingVar3 = (char*)&NtCurrentPeb()->SharedData->NtSystemRoot[253] + 1;

		// 0x20 is SPACE char.
		if ((*LoggingVar3 & ' ') != 0)
			WID_HIDDEN( LdrpLogEtwEvent(0x1496u, (ULONGLONG)DllBase, 0xFF, 0xFF); )
	}

	ULONG LoggingVar5 = 0;
	if (!ReturnVal && One == 1)
	{
		LoggingVar5 = 1;
		WID_HIDDEN( LdrpLogError(STATUS_DLL_INIT_FAILED, 0x1496u, LoggingVar5, 0i64); )
	}

	return ReturnVal;
}


NTSTATUS __fastcall LOADLIBRARY::fBasepLoadLibraryAsDataFileInternal(PUNICODE_STRING DllName, PWSTR Path, PWSTR Unknown, DWORD dwFlags, HMODULE* pBaseOfLoadedModule)
{
	// I have no control over datafile loads. It's only included to not break-up functionality.
	return BasepLoadLibraryAsDataFileInternal(DllName, Path, Unknown, dwFlags, pBaseOfLoadedModule);
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