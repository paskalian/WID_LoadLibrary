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
### LoadLibraryExW (Simplified & Explained)
```cpp
HMODULE __fastcall LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    // As we are assuming LoadLibraryA was called directly, there won't be no hFile nor dwFlags.
    // If you call this function directly you can of course give args.

    HMODULE ReturnModule;
    UNICODE_STRING UnicodeString;

    // Converts ANSI lpLibFileName into UNICODE, if it can't, returns 0.
    if (!(unsigned int)Basep8BitStringToDynamicUnicodeString(&UnicodeString, lpLibFileName))
        return 0;
    ReturnModule = LoadLibraryExW(UnicodeString.Buffer, hFile, dwFlags);
    RtlFreeUnicodeString(&UnicodeString);
    return ReturnModule;
}
```

That's why I said everything ends up in LoadLibraryExW, even if you call LoadLibraryExA, it transforms your ANSI path to UNICODE.
