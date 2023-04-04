![WID LOGO](Images/WID.svg "WID_LOGO")

<br>

# LEGAL NOTICE
<ins><b>I do not take responsibility for any misuse of these information in any way.</b></ins>

The purpose of these series are **only** to understand Windows better, there is a lot to discover.

# Information
There will be some terms I use you may not understand, so I wanted to explain them in here first.

### Functions
All the function implementations given below are my own, they are not guaranteed to represent the exact functionality.

### Levels
The depth level (it's what I say) of the functions, as the level get higher, the functions get less documented and harder to understand.
<br><br><br>
<a href="https://discord.gg/9qe38utdBJ" target="blank"><img align="center" src="https://raw.githubusercontent.com/rahuldkjain/github-profile-readme-generator/master/src/images/icons/Social/discord.svg" alt="9qe38utdBJ" height="30" width="30" /></a> [Discord](https://discord.gg/9qe38utdBJ "For other questions etc.")

<hr>

# What is LoadLibrary?
LoadLibrary is a Windows API function used for loading modules into programs.

The usage is pretty simple, you include Windows.h into your project, then you can use it.

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

Now that it may look confusing, but I will try to explain each function one by one.

<hr>

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
