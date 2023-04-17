![WID LOGO](Images/WID.svg "WID_LOGO")

<br>

# LEGAL NOTICE
<ins><b>I do not take responsibility for any misuse of these information in any way.</b></ins>

The purpose of these series are **only** to understand Windows better, there is a lot to discover.

# Information
### Compatibility
The project is designed specifically for x64 architecture, not tested in x86 architecture.

### Functions
All the function implementations given are my own, they are not guaranteed to represent the exact functionality.

# Usage
Pretty easy, you first include "WID.h" into your source file. Then you create a LOADLIBRARY instance with a path given, and that's it. Now you can almost see the entire loading process!
```cpp
#include "WID.h"

using namespace WID::Loader;

int main()
{
    LOADLIBRARY LoadDll(TEXT("PATH_TO_DLL.dll"));
}
```
The constructor takes in 3 arguments, which the last 2 are set by default.
#### PATH
Dll path, can be absolute or relative. **Must** be given.
#### FLAGS
Same flags as in LoadLibraryExW, you can check the possible values in [here](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw). Set to 0 by default.
#### LOAD TYPE (NOT USEFUL CURRENTLY)
If set to LOADTYPE::HIDDEN, Windows will not be informed about the loading of the dll. Set to LOADTYPE::DEFAULT by default.

<hr>

# What is LoadLibrary?
LoadLibrary is an easy to use Windows API function for loading Dynamic Link Libraries (DLLs) into programs.

To be able to use it you must first include <Windows.h> into your source file.

There are 4 widely used LoadLibrary functions
- [LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya "MSDN Reference")
- [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw "MSDN Reference")
- [LoadLibraryExA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa "MSDN Reference")
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw "MSDN Reference")

Even if they look like seperate, they all end up in **LoadLibraryExW** finally, wanna learn how? Keep reading.

<hr>

Here is a basic diagram to show what functions are called in order to load a module into a process (maybe not exact represantation).<br>

<p align="center">
<b>The path was given absolute and no flags were given</b>

<img src="https://github.com/paskalian/WID_LoadLibrary/blob/main/Images/Diagram.svg" alt="Diagram"/>
</p>

# Basic Explanations
## LoadLibrary
```cpp
#ifdef UNICODE
#define LoadLibrary  LoadLibraryW
#else
#define LoadLibrary  LoadLibraryA
#endif // !UNICODE
```
Not a function by itself but a macro instead, resolved into one of the according functions **LoadLibraryA** or **LoadLibraryW** depending on your character set being **Multi-byte** or **Unicode** respectively.
<br>
## LoadLibraryA
```cpp
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
```
In our use case it's just a small wrapper around LoadLibraryExA. Other way around you can see it provides a shortcut mechanism for loading "**twain_32.dll**".
<br>
## LoadLibraryW
```cpp
HMODULE __fastcall LOADLIBRARY::fLoadLibraryW(LPCWSTR lpLibFileName)
{
    return fLoadLibraryExW(lpLibFileName, 0, 0);
}
```
A wrapper for LoadLibraryExW.
<br>
## LoadLibraryExA
```cpp
HMODULE __fastcall LOADLIBRARY::fLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{    
    UNICODE_STRING Unicode;
    if (!Basep8BitStringToDynamicUnicodeString(&Unicode, lpLibFileName))
        return NULL;

    HMODULE Module = fLoadLibraryExW(Unicode.Buffer, hFile, dwFlags);
    RtlFreeUnicodeString(&Unicode);
    return Module;
}
```
Converts our ANSI given lpLibFileName into Unicode then calls LoadLibraryExW with it. In summary it's a wrapper for LoadLibraryExW, that's what I meant when I said all of the 4 functions end up in LoadLibraryExW.
<br>
## LoadLibraryExW
```cpp
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
```
Converts our given flags to it's own converted flags and calls LdrLoadDll, other way around requires the dll to be loaded as a datafile, which we are not interested in right now.
<br>
## LdrLoadDll
```cpp
NTSTATUS __fastcall LOADLIBRARY::fLdrLoadDll(PWSTR DllPath, PULONG pFlags, PUNICODE_STRING DllName, PVOID* BaseAddress)
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
        FlagUsed |= ((ActualFlags & CNVTD_DONT_RESOLVE_DLL_REFERENCES)           ? LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE : NULL);
        FlagUsed |= ((ActualFlags & CNVTD_LOAD_LIBRARY_REQUIRE_SIGNED_TARGET)    ? LOAD_LIBRARY_REQUIRE_SIGNED_TARGET : NULL);

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
```
Flags are re-converted, a check is made to see if the current thread is a worker thread, our path is initialized then LdrpLoadDll is getting called.
<br>
## LdrpLoadDll
```cpp
NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDll(PUNICODE_STRING DllName, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, LDR_DATA_TABLE_ENTRY** DllEntry)
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
```
A fairly smaller one than the last, the main purpose of it is to divide our path given into meaningful parts by LdrpPreprocessDllName then calling LdrpLoadDllInternal using that.
<br>
## LdrpLoadDllInternal
```cpp
NTSTATUS __fastcall LOADLIBRARY::fLdrpLoadDllInternal(PUNICODE_STRING FullPath, LDR_UNKSTRUCT* DllPathInited, ULONG Flags, ULONG LdrFlags, PLDR_DATA_TABLE_ENTRY LdrEntry, PLDR_DATA_TABLE_ENTRY LdrEntry2, PLDR_DATA_TABLE_ENTRY* DllEntry, NTSTATUS* pStatus, ULONG Zero)
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

    WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x379, "LdrpLoadDllInternal", 3, "DLL name: %wZ\n", FullPath); )

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
            if (!(NT_SUCCESS((int)(Status + 0x80000000))) || Status == STATUS_IMAGE_LOADED_AS_PATCH_IMAGE)
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

    // LoadNotificationsSent (0x8) | PackagedBinary (0x1)
    // Because the LdrFlags was sent 0x4 (ImageDll), we can ignore this one too.
    if (LdrFlags == (LoadNotificationsSent | PackagedBinary) && LdrEntry)
        LdrpDereferenceModule(LdrEntry);

    // Actually returns what LdrpLogInternal returns.
    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0x52E, "LdrpLoadDllInternal", 4, "Status: 0x%08lx\n", *pStatus); )
    return *pStatus;
}
```
The main course of action of this function is to check whether the dll was already loaded and waiting to be executed, or is going to be patched, or a new dll is going to be loaded, if it's a new dll (which is our case) it first goes by LdrpProcessWork to start the mapping process, then after that call succeeds goes on by LdrpPrepareModuleForExecution to execute the mapped dll.
<br>
## LdrpProcessWork
```cpp
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

            WID_HIDDEN( Status = LdrpLogInternal("minkernel\\ntdll\\ldrmap.c", 0x7D2, "LdrpProcessWork", 0, "Unable to load DLL: \"%wZ\", Parent Module: \"%wZ\", Status: 0x%x\n", LoadContext, ((UINT_PTR)&LoadContext->Entry->FullDllName & (UINT_PTR)LoadContext->Entry >> 64), Status); )
            // This part is for failed cases so we can ignore it.
            if (Status == STATUS_DLL_NOT_FOUND)
            {
                WID_HIDDEN( LdrpLogError(STATUS_DLL_NOT_FOUND, 0x19, 0, LoadContext); )
                WID_HIDDEN( LdrpLogDeprecatedDllEtwEvent(LoadContext); )
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

        RtlEnterCriticalSection(LdrpWorkQueueLock);
        --(*LdrpWorkInProgress);
        if (*LdrpWorkQueue != (LIST_ENTRY*)LdrpWorkQueue || (SetWorkCompleteEvent = TRUE, *LdrpWorkInProgress != 1))
            SetWorkCompleteEvent = FALSE;
        Status = RtlLeaveCriticalSection(LdrpWorkQueueLock);
        if (SetWorkCompleteEvent)
            Status = ZwSetEvent(*LdrpWorkCompleteEvent, 0);
    }

    return Status;
}
```
Goes in an according direction depending by the path type given, in our case we have an absolute path, so we continue by LdrpMapDllFullPath.
<br>
## LdrpMapDllFullPath
```cpp
NTSTATUS __fastcall LOADLIBRARY::fLdrpMapDllFullPath(PLDRP_LOAD_CONTEXT LoadContext)
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
```
Sets up a LDRP_FILENAME_BUFFER structure, basically representing each portion of a path (base part, absolute part, etc.), hashes the **base** dll name and checks if it was already loaded, if it's not (our case) it goes on by calling LdrpMapDllNtFileName.
<br>
## LdrpMapDllNtFileName
```cpp
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
    WID_HIDDEN( LdrpLogDllState((ULONGLONG)DllEntry->DllBase, &DllEntry->FullDllName, 0x14A5); )
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
    if    (*LdrpAuditIntegrityContinuity && (Status = LdrpValidateIntegrityContinuity(LoadContext, FileHandle), !NT_SUCCESS(Status)) && *LdrpEnforceIntegrityContinuity || 
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
```
Opens the file with NtOpenFile, creates a section using NtCreateSection to be able to map the dll, continues with calling LdrpMapDllWithSectionHandle.
<br>
## LdrpMapDllWithSectionHandle
```cpp
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
                WID_HIDDEN( LdrpLogDllState((ULONG)DllEntry->DllBase, &DllEntry->FullDllName, 0x14AEu); )
                Status2 = STATUS_SUCCESS;
                DllEntry->DdagNode->State = LdrModulesReadyToRun;
            }
        }
    }

    return Status2;
}
```
Maps a view of section inside LdrpMinimalMapModule, validates the image inside LdrpCompleteMapModule, handles relocations inside LdrpProcessMappedModule, updates state inside LdrpCorProcessImports, goes on by calling LdrpMapAndSnapDependency.
<br>
## LdrpMapAndSnapDependency
```cpp
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
            DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
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
```
Prepares the Import Address Table (IAT) by calling LdrpPrepareImportAddressTableForSnap, loads the imports of the dll getting loaded, sets the state, continues on by calling LdrpSnapModule which I am quite frank about the actual functionality, but I've seen it handling exports.
<br>
## LdrpPrepareImportAddressTableForSnap
```cpp
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
```
As the function name, prepares the Import Address Table (IAT) for our loaded dll. After this function we go back to LdrpLoadDllInternal because the mapping process is complete. Proceeding with calling LdrpPrepareModuleForExecution.
<br>
## LdrpPrepareModuleForExecution
```cpp
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
```
Adds a service tag to our module by LdrModulesCondensed, continues by LdrModulesReadyToInit acquiring a Loader lock first then calling LdrpInitializeGraphRecurse.
<br>
## LdrpInitializeGraphRecurse
```cpp
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
```
Does some prior check on the upper area of the function if our DdagNode had dependencies (in our loading case it doesn't so we skip over all the do-while loop), checks for errors and if there are any, sets the state to failed and returns. Otherwise (our case) continues on by calling LdrpInitializeNode.
<br>
## LdrpInitializeNode
```cpp
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
```
Sets the state to initializing, goes on by checking if it's purpose is to patch the image (not in our case), if it is, it patches the image by calling LdrpApplyPatchImage, if it's not it goes on by calling LdrpCallTlsInitializers which is self explanatory and finally it calls LdrpCallInitRoutine.
<br>
## LdrpCallInitRoutine
```cpp
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
```
Does prior checks and calls DllMain which finishes the loading process.
