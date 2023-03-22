![WINSERIES_LOGO](Images/WinSeries_0x1.png "WINSERIES_LOGO")

<br>

# LEGAL NOTICE
<ins><b>I do not take responsibility for any misuse of these information in any way.</b></ins>

The purpose of these series are **only** to understand Windows better, there is a lot to discover.

# Information
There will be some terms I use you may not understand, so I wanted to explain them in here first.

### Levels
The depth level (it's what I say) of the functions, as the level get higher, the functions get less documented and harder to understand.

<hr>

# What is LoadLibrary?
LoadLibrary is a Windows API function used for loading modules into programs.

The usage is pretty simple, you include Windows.h into your project, then you can use it.

There is 4 main LoadLibrary functions you can use
- [LoadLibraryA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya "MSDN Reference")
- [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw "MSDN Reference")
- [LoadLibraryExA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa "MSDN Reference")
- [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw "MSDN Reference")

Even if they look like seperate, they all end up in **LoadLibraryExW** finally, wanna learn how? Keep reading.

# Level 1
All the functions I've said above are declared in KERNEL32.DLL, but their actual definitions are inside KERNELBASE.dll, because both these modules are well documented and have their own PDB, it wasn't that hard to understand them.

<hr>

## LoadLibraryA
### LoadLibraryA (IDA Pseudocode)
```cpp
HMODULE __fastcall LoadLibraryA(LPCSTR lpLibFileName)
{
  PCHAR Heap; // rax
  PCHAR Heap_2; // rbx
  HMODULE ReturnModule; // rsi

  if ( !lpLibFileName )
    return LoadLibraryExA(lpLibFileName, 0i64, 0);
  if ( _stricmp(lpLibFileName, "twain_32.dll") )
    return LoadLibraryExA(lpLibFileName, 0i64, 0);
  // 260 = MAX_PATH
  Heap = (PCHAR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, (unsigned int)KernelBaseGlobalData, 260i64);
  Heap_2 = Heap;
  if ( !Heap )
    return LoadLibraryExA(lpLibFileName, 0i64, 0);
  if ( GetWindowsDirectoryA(Heap, 0xF7u) - 1 > 0xF5
    || (strncat_s(Heap_2, 260ui64, "\\twain_32.dll", 0xDui64), (ReturnModule = LoadLibraryA(Heap_2)) == 0i64) )
  {
    RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0i64, Heap_2);
    return LoadLibraryExA(lpLibFileName, 0i64, 0);
  }
  RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0i64, Heap_2);
  return ReturnModule;
}
```
### LoadLibraryA (Simplified & Explained)
```cpp
HMODULE __fastcall LoadLibraryA(LPCSTR lpLibFileName)
{
    // If no path was given.
    if (!lpLibFileName)
        return LoadLibraryExA(lpLibFileName, 0, 0);
    // If path isn't 'twain_32.dll'
    // This is where our LoadLibrary calls mostly end up.
    if (_stricmp(lpLibFileName, "twain_32.dll"))
        return LoadLibraryExA(lpLibFileName, 0, 0);

    // If path is 'twain_32.dll'
    // Windows probably uses this to make itself a shortcut, while we are using it the code won't reach here.
    PCHAR Heap = (PCHAR)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, KernelBaseGlobalData, MAX_PATH);
    if (!Heap)
        return LoadLibraryExA(lpLibFileName, 0, 0);

    HMODULE ReturnModule;
    // Heap receives the Windows path (def: C:\Windows)
   
    // The BufferSize check made against GetWindowsDirectoryA is to see if it actually received. If it's bigger than BufferSize 
    // then GetWindowsDirectoryA returned the size needed (in summary it fails)
    
    // If this check doesn't fail '\twain_32.dll' is appended to the Windows path (def: C:\Windows\twain_32.dll)
    // Then this final module is loaded into the program.
    // If it can't load, it tries to load it directly and returns from there.
    if (GetWindowsDirectoryA(Heap, HeapSize) - 1 > BufferSize ||
       (strncat_s(Heap, MAX_PATH, "\\twain_32.dll", strlen("\\twain_32.dll")), (ReturnModule = LoadLibraryA(Heap)) == 0))
    {
        RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
        return LoadLibraryExA(lpLibFileName, 0, 0);
    }
    RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Heap);
    return ReturnModule;
}
```

So as you can also see, other than doing some checks, it ends up in LoadLibraryExA.
<hr>

## LoadLibraryW
### LoadLibraryW (IDA Pseudocode)
```cpp
HMODULE __fastcall LoadLibraryW(LPCWSTR lpLibFileName)
{
  return LoadLibraryExW(lpLibFileName, 0i64, 0);
}
```

Self explanatory.
<hr>

## LoadLibraryExA
### LoadLibraryExA (IDA Pseudocode)
```cpp
HMODULE __fastcall LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
  HMODULE ReturnModule; // rbx
  UNICODE_STRING UnicodeString; // [rsp+20h] [rbp-18h] BYREF

  if ( !(unsigned int)Basep8BitStringToDynamicUnicodeString(&UnicodeString, lpLibFileName) )
    return 0i64;
  ReturnModule = LoadLibraryExW(UnicodeString.Buffer, hFile, dwFlags);
  RtlFreeUnicodeString(&UnicodeString);
  return ReturnModule;
}
```
### LoadLibraryExA (Simplified & Explained)
```cpp
HMODULE __fastcall LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    // As we are assuming LoadLibraryA was called directly, there won't be no hFile nor dwFlags.
    // If you call this function directly you can of course give args.

    HMODULE ReturnModule;
    UNICODE_STRING UnicodeString;

    // Converts ANSI lpLibFileName into UNICODE, if it can't, returns 0.
    if (Basep8BitStringToDynamicUnicodeString(&UnicodeString, lpLibFileName) == FALSE)
        return 0;
    ReturnModule = LoadLibraryExW(UnicodeString.Buffer, hFile, dwFlags);
    RtlFreeUnicodeString(&UnicodeString);
    return ReturnModule;
}
```

That's why I said everything ends up in LoadLibraryExW, even if you call LoadLibraryExA, it transforms your ANSI path to UNICODE.

<hr>

# Level 2
Even though still most of the stuff is documented, things get a little trickier.

## LoadLibraryExW
### LoadLibraryExW (IDA Pseuodocode)
```cpp
HMODULE __stdcall LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
  DWORD FlagCheck; // esi
  NTSTATUS NtStatus; // eax
  unsigned __int16 StrByteLen; // cx
  NTSTATUS LibraryAsDataFileInternal; // eax
  NTSTATUS NtStatus2; // edi
  __int64 NtStatus3; // rcx
  unsigned int v11; // eax
  bool IsStrByteLen2; // zf
  __int64 v13; // [rsp+30h] [rbp-20h] BYREF
  __int64 v14; // [rsp+38h] [rbp-18h] BYREF
  UNICODE_STRING DllName; // [rsp+40h] [rbp-10h] BYREF
  unsigned int NotSureFlags; // [rsp+70h] [rbp+20h] BYREF
  HMODULE BaseOfLoadedDll; // [rsp+88h] [rbp+38h] BYREF

  if ( !lpLibFileName )                         // If no filename was given to load
    goto INVALID_PARAM;
  if ( hFile )                                  // This directly proves hFile must be zero (msdn)
    goto INVALID_PARAM;
  if ( (dwFlags & 0xFFFF0000) != 0 )            // If a high bit (unsupported) is set
    goto INVALID_PARAM;
  FlagCheck = dwFlags & 0x42;                   // If LOAD_LIBRARY_AS_DATAFILE (0x2) and LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) are both set in dwFlags
  if ( FlagCheck == 0x42 )
    goto INVALID_PARAM;
  NtStatus = RtlInitUnicodeStringEx(&DllName, lpLibFileName);
  if ( NtStatus < 0 )
    goto NTFAIL;
  StrByteLen = DllName.Length;
  if ( !DllName.Length )
    goto INVALID_PARAM;
  // To sum up the purpose is to reinitialize the length in byte format to length in character amount.
  do
  {
    if ( DllName.Buffer[((unsigned __int64)StrByteLen >> 1) - 1] != 0x20 )// Divides StrByteLen by 2 to get the amount of chars (because we are dealing with wchar every character is 2 bytes). Then subtracts 1 from that because arrays' start from idx 0. From there on (starting with the last char) checks if there's an empty char.
      break;
    // Checks if it's in the first character (because it started from the last this is actually the last idx)
    IsStrByteLen2 = StrByteLen == 2;
    StrByteLen -= 2;
    DllName.Length = StrByteLen;
  }
  while ( !IsStrByteLen2 );
  if ( !StrByteLen )                            // Checks if StrByteLen is invalid.
  {
INVALID_PARAM:
    NtStatus3 = 0xC000000Di64;                  // STATUS_INVALID_PARAMETER
    goto FAIL;
  }
  BaseOfLoadedDll = 0i64;
  // If none of LOAD_LIBRARY_AS_DATAFILE (0x2) and LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE (0x40) and LOAD_LIBRARY_AS_IMAGE_RESOURCE (0x20) is defined goes in, otherwise the Dll will not (REALLY) be loaded.
  if ( (dwFlags & 0x62) == 0 )
  {
    NotSureFlags = 0;
    v11 = 0;
    if ( (dwFlags & 1) != 0 )                   // If DONT_RESOLVE_DLL_REFERENCES is set
    {
      v11 = 2;
      NotSureFlags = 2;
    }
    if ( (dwFlags & 0x80u) != 0 )               // If LOAD_LIBRARY_REQUIRE_SIGNED_TARGET is set
    {
      v11 |= 0x800000u;
      NotSureFlags = v11;
    }
    if ( (dwFlags & 4) != 0 )                   // If UNDOCUMENTED flag is set (CAN'T BE SET BY USER I ASSUME)
    {
      v11 |= 4u;
      NotSureFlags = v11;
    }
    if ( (dwFlags & 0x8000) != 0 )              // If UNDOCUMENTED flag is set (CAN'T BE SET BY USER I ASSUME)
      NotSureFlags = v11 | 0x80000000;
    // The AND operation doesn't change anything, only the first bit is set by the OR operation. The first bit sets DONT_RESOLVE_DLL_REFERENCES flag, which results in the Dll's DllMain not getting called.
    // Some places say the first arg is PWCHAR PathToFile, I don't really see that.
    // The second may be dwFlags (combined with it at least)
    NtStatus2 = LdrLoadDll(dwFlags & 0x7F08 | 1i64, &NotSureFlags, &DllName, &BaseOfLoadedDll);// The AND operation doesn't change anything, only the first bit is set by the OR operation. The first bit sets DONT_RESOLVE_DLL_REFERENCES flag, which results in the Dll's DllMain not getting called.
    goto END;
  }
  NtStatus = LdrGetDllPath(DllName.Buffer, dwFlags & 0x7F08, &v13, &v14);
  if ( NtStatus < 0 )
  {
NTFAIL:
    NtStatus3 = (unsigned int)NtStatus;
    goto FAIL;
  }
  LibraryAsDataFileInternal = BasepLoadLibraryAsDataFileInternal(
                                (unsigned int)&DllName,
                                v13,
                                v14,
                                dwFlags,
                                (__int64)&BaseOfLoadedDll);
  NtStatus2 = LibraryAsDataFileInternal;
  if ( (int)(LibraryAsDataFileInternal + 0x80000000) >= 0
    && LibraryAsDataFileInternal != 0xC000000F
    && (dwFlags & 0x20) != 0 )
  {
    if ( FlagCheck )
      NtStatus2 = BasepLoadLibraryAsDataFileInternal(
                    (unsigned int)&DllName,
                    v13,
                    v14,
                    dwFlags & 0x42,
                    (__int64)&BaseOfLoadedDll);
  }
  RtlReleasePath(v13);
END:
  if ( NtStatus2 >= 0 )
    return BaseOfLoadedDll;
  NtStatus3 = (unsigned int)NtStatus2;
FAIL:
  BaseSetLastNTError(NtStatus3);
  return 0i64;
}
```
### LoadLibraryExW (Simplified & Explained)
```cpp
#define LOADLIBRARY_ISDATAFILE  (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE)
#define LOADLIBRARY_7F08        (LOAD_LIBRARY_SEARCH_SYSTEM32_NO_FORWARDER | LOAD_LIBRARY_SAFE_CURRENT_DIRS | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_WITH_ALTERED_SEARCH_PATH)
#define LOADLIBRARY_ASDATAFILE  (LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_DATAFILE)
#define STATUS_NO_SUCH_FILE     0xC000000F

HMODULE __stdcall LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    NTSTATUS Status;

    DWORD ConvertedFlags;
    HMODULE BaseOfLoadedDll;

    DWORD DatafileFlags = dwFlags & LOADLIBRARY_ASDATAFILE;
    // If no DllName was given OR hFile was given (msdn states that hFile must be 0) OR dwFlags is set to an unknown value OR *both* the Datafile flags are set (they cannot be used together).
    if (!lpLibFileName || hFile || ((dwFlags & 0xFFFF0000) != 0) || (DatafileFlags == LOADLIBRARY_ASDATAFILE))
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return 0;
    }

    UNICODE_STRING DllName;
    Status = RtlInitUnicodeStringEx(&DllName, lpLibFileName);
    if (NT_SUCCESS(Status) == FALSE)
    {
        BaseSetLastNTError(Status);
        return 0;
    }

    USHORT DllNameLen = DllName.Length;
    if (!DllName.Length)
    {
        BaseSetLastNTError(STATUS_INVALID_PARAMETER);
        return 0;
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
        return 0;
    }

    BaseOfLoadedDll = 0;

    // If the dll is not getting loaded as a datafile (loaded normally).
    if ((dwFlags & LOADLIBRARY_ISDATAFILE) == 0)
    {
        // Converts the actual flags into it's own flag format. Most flags are discarded (only used if loaded as datafile).
        // Only flags that can go through are DONT_RESOLVE_DLL_REFERENCES, LOAD_PACKAGED_LIBRARY, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET and LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY
        ConvertedFlags = 0;
        if ((dwFlags & DONT_RESOLVE_DLL_REFERENCES) != 0)
            ConvertedFlags |= 0x2;
        if ((dwFlags & LOAD_PACKAGED_LIBRARY) != 0)
            ConvertedFlags |= 0x4;
        if ((dwFlags & LOAD_LIBRARY_REQUIRE_SIGNED_TARGET) != 0)
            ConvertedFlags |= 0x800000;
        if ((dwFlags & LOAD_LIBRARY_OS_INTEGRITY_CONTINUITY) != 0)
            ConvertedFlags |= 0x80000000;

        // Evaluates dwFlags to get meaningful flags, includes DONT_RESOLVE_DLL_REFERENCES finally.
        // But it doesn't matter because the first param LdrLoadDll takes actually a (PWCHAR PathToFile), so I have no idea why that's done.
        Status = LdrLoadDll((PWCHAR)((dwFlags & LOADLIBRARY_7F08) | 1), &ConvertedFlags, &DllName, &BaseOfLoadedDll);
        if (NT_SUCCESS(Status))
            return BaseOfLoadedDll;

        BaseSetLastNTError(Status);
        return 0;
    }

    PWSTR Path;
    PWSTR Unknown;
    // Gets the Dll path.
    Status = LdrGetDllPath(DllName.Buffer, (dwFlags & LOADLIBRARY_7F08), &Path, &Unknown);
    if (NT_SUCCESS(Status) == FALSE)
    {
        BaseSetLastNTError(Status);
        return 0;
    }
    
    // First step into loading a module as datafile.
    Status = BasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, dwFlags, &BaseOfLoadedDll);
    // If the Status is only success (excludes warnings) AND if the module is image resource, loads again. I don't know why.
    if (NT_SUCCESS(Status + 0x80000000) && Status != STATUS_NO_SUCH_FILE && (dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE) != 0)
    {
        if (DatafileFlags)
            Status = BasepLoadLibraryAsDataFileInternal(&DllName, Path, Unknown, DatafileFlags, &BaseOfLoadedDll);
    }

    RtlReleasePath(Path);
    BaseSetLastNTError(Status);
    return 0;
}
```

So from there on, we can see there is 2 pathways;
1. LdrLoadDll
2. BasepLoadLibraryAsDataFileInternal

I will be focused on LdrLoadDll and so on because that's the main way, but will check BasepLoadLibraryAsDataFileInternal too.

<hr>

# Level 3
The functions get even less documented, googling around to gather information gets you less accurate results, checking out yourself might be the best course here.
