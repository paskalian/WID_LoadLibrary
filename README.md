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
### LoadLibraryA (Simplified)
```cpp
// TO DO, PUT THE SIMPLIFIED AND EXPLAINED CODE IN HERE.
```
