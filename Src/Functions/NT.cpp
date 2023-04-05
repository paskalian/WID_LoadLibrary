#include "NT.h"

// Implemented.
// Variables
DWORD*                  LdrpPolicyBits                  = nullptr;
HANDLE*                 LdrpMainThreadToken             = nullptr;
DWORD*                  LdrInitState                    = nullptr;
DWORD*                  LoadFailure                     = nullptr;
PRTL_CRITICAL_SECTION   LdrpWorkQueueLock               = nullptr;
DWORD*                  LdrpWorkInProgress              = nullptr;
LIST_ENTRY**            LdrpWorkQueue                   = nullptr;
PHANDLE                 LdrpWorkCompleteEvent           = nullptr;
KUSER_SHARED_DATA*      kUserSharedData                 = (KUSER_SHARED_DATA*)0x7FFE0000;
DWORD*                  LdrpUseImpersonatedDeviceMap    = nullptr;
DWORD*                  LdrpAuditIntegrityContinuity    = nullptr;
DWORD*                  LdrpEnforceIntegrityContinuity  = nullptr;
DWORD*                  LdrpFatalHardErrorCount         = nullptr;
DWORD*                  UseWOW64                        = nullptr;
PRTL_SRWLOCK			LdrpModuleDatatableLock         = nullptr;
PHANDLE					qword_17E238                    = nullptr;
LDR_DATA_TABLE_ENTRY**  LdrpImageEntry                  = nullptr;
PUNICODE_STRING			LdrpKernel32DllName             = nullptr;
UINT_PTR*               LdrpAppHeaders                  = nullptr;
PHANDLE					LdrpLargePageDllKeyHandle       = nullptr;
ULONG**                 LdrpLockMemoryPrivilege         = nullptr;
ULONG64*                LdrpMaximumUserModeAddress      = nullptr;
UINT_PTR*               LdrpMapAndSnapWork              = nullptr;
LIST_ENTRY*             LdrpHashTable                   = nullptr;
PVOID*                  LdrpHeap                        = nullptr;
BOOLEAN*                LdrpIsHotPatchingEnabled        = nullptr;
LDR_DATA_TABLE_ENTRY**  LdrpRedirectionModule           = nullptr;
ULONG64**               qword_1993A8                    = nullptr;
LONG*                   NtdllBaseTag                    = nullptr;
FUNCTION_TABLE_DATA*    stru_199520                     = nullptr;
UINT_PTR*               qword_199530                    = nullptr;
LDR_DATA_TABLE_ENTRY**  LdrpNtDllDataTableEntry         = nullptr;
UINT_PTR*               qword_1993B8                    = nullptr;
DWORD*                  dword_19939C                    = nullptr;
DWORD*                  LoadFailureOperational          = nullptr;
DWORD*                  dword_199398                    = nullptr;
UINT_PTR***             qword_1843B8                    = nullptr;
UINT_PTR*               qword_1843B0                    = nullptr;
UINT_PTR*               LdrpCurrentDllInitializer       = nullptr;
LPVOID**                LdrpProcessInitContextRecord    = nullptr;
PRTL_SRWLOCK			LdrpTlsLock                     = nullptr;
TLS_ENTRY**             LdrpTlsList                     = nullptr;

tLdrpManifestProberRoutine LdrpManifestProberRoutine    = nullptr;
tLdrpRedirectionCalloutFunc LdrpRedirectionCalloutFunc  = nullptr;

// Functions
PEB* NtCurrentPeb()
{
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer) // CHECKED.
{
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
}

NTSTATUS __fastcall LdrpFastpthReloadedDll(PUNICODE_STRING FullPath, ULONG Flags, PLDR_DATA_TABLE_ENTRY LdrEntry, LDR_DATA_TABLE_ENTRY** DllEntry)
{
    NTSTATUS Status;

    PUNICODE_STRING PathUsed;
    LDR_DATA_TABLE_ENTRY* pDllEntry;
    LDR_DDAG_STATE DdagState;

    DdagState = LdrModulesPlaceHolder;
    Status = STATUS_NOT_FOUND;

    if (Flags & LOAD_LIBRARY_AS_IMAGE_RESOURCE)
    {
        PathUsed = FullPath;
        FullPath = 0;
    }
    else
    {
        // If an absolute path was sent from LoadLibrary it will have 0x200 (LOAD_LIBRARY_SEARCH_APPLICATION_DIR), but the if is checking for not so it can be ignored.
        if ((Flags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR) == 0)
            return Status;

        PathUsed = nullptr;
    }

    Status = LdrpFindLoadedDllByName(PathUsed, FullPath, Flags, DllEntry, &DdagState);
    if (NT_SUCCESS(Status))
    {
        pDllEntry = *DllEntry;
        if (pDllEntry->LoadReason == LoadReasonPatchImage)
        {
            Status = STATUS_IMAGE_LOADED_AS_PATCH_IMAGE;
            LdrpLogEtwHotPatchStatus(&(*LdrpImageEntry)->BaseDllName, pDllEntry, 0, STATUS_IMAGE_LOADED_AS_PATCH_IMAGE, 2u);
        }
        else
        {
            Status = STATUS_NOT_FOUND;
            if (DdagState == LdrModulesReadyToRun)
            {
                Status = LdrpIncrementModuleLoadCount(pDllEntry);
                if (NT_SUCCESS(Status))
                {
                    Status = LdrpBuildForwarderLink(LdrEntry, pDllEntry);
                    // This is where we most likely end up on a normal call from LoadLibraryExW
                    if (NT_SUCCESS(Status))
                        return Status;

                    BOOLEAN IsWorkerThread = (!(NtCurrentTeb()->SameTebFlags & LoadOwner));
                    if (IsWorkerThread)
                        LdrpDrainWorkQueue(WaitLoadComplete);

                    LdrpDecrementModuleLoadCountEx(pDllEntry, 0);
                    if (IsWorkerThread)
                        LdrpDropLastInProgressCount();
                }
            }
        }

        LdrpDereferenceModule(*DllEntry);
        *DllEntry = nullptr;
    }

    return Status;
}

NTSTATUS __fastcall LdrpIncrementModuleLoadCount(LDR_DATA_TABLE_ENTRY* LdrEntry)
{
    NTSTATUS Status = STATUS_SUCCESS;

    RtlAcquireSRWLockExclusive(LdrpModuleDatatableLock);

    LDR_DDAG_NODE* DdagNode = LdrEntry->DdagNode;
    ULONG LoadCount = DdagNode->LoadCount;
    if (LoadCount != -1)
    {
        if (LoadCount)
        {
            DdagNode->LoadCount = LoadCount + 1;
        }
        else if (NtCurrentTeb()->SameTebFlags & LoadOwner)
        {
            ++DdagNode->LoadWhileUnloadingCount;
        }
        else
        {
            Status = STATUS_DLL_NOT_FOUND;
        }
    }

    RtlReleaseSRWLockExclusive(LdrpModuleDatatableLock);

    return Status;
}

VOID __fastcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString) // CHECKED.
{
    WCHAR* Buffer;

    Buffer = UnicodeString->Buffer;
    if (Buffer)
    {
        NtdllpFreeStringRoutine(Buffer);
        //*UnicodeString = 0;
        memset(UnicodeString, 0, sizeof(UNICODE_STRING));
    }
}

VOID __fastcall LdrpFreeUnicodeString(PUNICODE_STRING String)
{
    WCHAR* Buffer;

    Buffer = String->Buffer;
    if (Buffer)
    {
        NtdllpFreeStringRoutine(Buffer);
        String->Buffer = 0;
    }
    String->Length = 0;
    String->MaximumLength = 0;
}

ULONG __fastcall RtlGetCurrentServiceSessionId(VOID) // CHECKED ?
{
     LPVOID Return = NtCurrentPeb()->SharedData;

    if (Return)
        Return = (LPVOID)(*(DWORD*)Return);
    return (ULONG)Return;
}

USHORT __fastcall LdrpGetBaseNameFromFullName(PUNICODE_STRING BaseName, PUNICODE_STRING FullName)
{
    USHORT StrLen = BaseName->Length >> 1;
    if (StrLen)
    {
        PWCHAR Buffer = BaseName->Buffer;
        do
        {
            if (Buffer[StrLen - 1] == '\\')
                break;
            if (Buffer[StrLen - 1] == '/')
                break;
            --StrLen;
        } while (StrLen);
    }

    USHORT ByteLen = 2 * StrLen;

    USHORT Return = BaseName->MaximumLength - ByteLen;
    FullName->Length = BaseName->Length - ByteLen;
    FullName->MaximumLength = Return;
    FullName->Buffer = &BaseName->Buffer[StrLen];
    return Return;
}

PWCHAR __fastcall RtlGetNtSystemRoot()
{
    if (RtlGetCurrentServiceSessionId())
        return (PWCHAR)((char*)NtCurrentPeb()->SharedData + 30);
    else
        return kUserSharedData->NtSystemRoot;
}

BOOLEAN __fastcall LdrpHpatAllocationOptOut(PUNICODE_STRING FullDllName)
{
    UNICODE_STRING NtString; // [rsp+30h] [rbp-18h] BYREF

    if ((NtCurrentPeb()->ProcessParameters->Flags & 0x2000000) == 0 || *FullDllName->Buffer == '\\')
        return 0;
    PWSTR NtSystemRoot = RtlGetNtSystemRoot();
    RtlInitUnicodeStringEx(&NtString, NtSystemRoot);
    return FullDllName->Length < NtString.Length || RtlCompareUnicodeStrings(FullDllName->Buffer, NtString.Length >> 1, NtString.Buffer, NtString.Length >> 1, 1u) != 0;
}

NTSTATUS __fastcall LdrpCorValidateImage(PIMAGE_DOS_HEADER DosHeader)
{
    NTSTATUS Status;
 
    PIMAGE_FILE_HEADER ImageFileHeader;
    UINT_PTR LastRVASection;
    Status = RtlpImageDirectoryEntryToDataEx(DosHeader, TRUE, IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED, &LastRVASection, (PIMAGE_FILE_HEADER*)&ImageFileHeader);
    if (!NT_SUCCESS(Status))
        ImageFileHeader = 0;
    return ImageFileHeader != 0 ? STATUS_INVALID_IMAGE_FORMAT : 0;
}

NTSTATUS __fastcall LdrpCorFixupImage(PIMAGE_DOS_HEADER DosHeader)
{
    NTSTATUS Status;

    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(DosHeader);
    ULONG64 LastRVASection;
    PIMAGE_COR20_HEADER CorHeader = nullptr;
    Status = RtlpImageDirectoryEntryToDataEx(DosHeader, 1, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, &LastRVASection, &CorHeader);
    if (!NT_SUCCESS(Status) || !CorHeader)
        return Status;

    if (NtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && NtHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && (CorHeader->Flags & 2) == 0)
    {
        ULONG64* pSizeOfHeapCommit = &NtHeader->OptionalHeader.SizeOfHeapCommit;
        PBYTE UnknownCalc =   (PBYTE)&NtHeader->OptionalHeader             +
                        (32 * NtHeader->FileHeader.NumberOfSections) + 
                        (8 * NtHeader->FileHeader.NumberOfSections)  + 
                        NtHeader->FileHeader.SizeOfOptionalHeader;

        UINT_PTR NumberOfBytesToProtect = 0x1000;
        if ((unsigned __int64)(UnknownCalc - (PBYTE)DosHeader + 0x10) <= 0x1000)
        {
            ULONG OldAccessProtection;
            Status = ZwProtectVirtualMemory((HANDLE)-1, (PVOID*)&DosHeader, (PULONG)&NumberOfBytesToProtect, PAGE_READWRITE, &OldAccessProtection);
            if (NT_SUCCESS(Status))
            {
                memmove(NtHeader->OptionalHeader.DataDirectory, &NtHeader->OptionalHeader.SizeOfHeapCommit, UnknownCalc - (PBYTE)pSizeOfHeapCommit);
                *(ULONG64*)&NtHeader->OptionalHeader.LoaderFlags = NtHeader->OptionalHeader.SizeOfHeapReserve;
                *pSizeOfHeapCommit = (NtHeader->OptionalHeader.SizeOfStackCommit) & 0xFFFFFFFF00000000;

                NtHeader->OptionalHeader.SizeOfHeapReserve  = (NtHeader->OptionalHeader.SizeOfStackCommit)  & UINT_MAX;
                NtHeader->OptionalHeader.SizeOfStackCommit  = (NtHeader->OptionalHeader.SizeOfStackReserve) & 0xFFFFFFFF00000000;
                NtHeader->OptionalHeader.SizeOfStackReserve = (NtHeader->OptionalHeader.SizeOfStackReserve) & UINT_MAX;
                NtHeader->OptionalHeader.ImageBase          = (NtHeader->OptionalHeader.ImageBase)          & 0xFFFFFFFF00000000;
                NtHeader->FileHeader.SizeOfOptionalHeader   += 0x10;

                NtHeader->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                ZwProtectVirtualMemory((HANDLE)-1, (PVOID*)&DosHeader, (PULONG)&NumberOfBytesToProtect, OldAccessProtection, &OldAccessProtection);
            }
        }
        else
        {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    else
    {
        WORD Machine = NtHeader->FileHeader.Machine;
        if (Machine < kUserSharedData->ImageNumberLow)
            return STATUS_INVALID_IMAGE_FORMAT;

        Status = STATUS_SUCCESS;
        if (Machine > kUserSharedData->ImageNumberHigh)
            return STATUS_INVALID_IMAGE_FORMAT;
    }
    return Status;
}

NTSTATUS __fastcall LdrpFindLoadedDllByNameLockHeld(PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, ULONG64 Flags, LDR_DATA_TABLE_ENTRY** pLdrEntry, ULONG BaseNameHashValue)
{
    LIST_ENTRY* pHashIdx;
    
    LDR_DDAG_NODE* DdagNode;

    // Parse entire hash table. Maybe I use it later on.
    //for (int idx = 0; idx < 32; idx++)
    //{
    //    LIST_ENTRY* IdxHead = &LdrpHashTable[idx];
    //    LIST_ENTRY* IdxEntry = IdxHead->Flink;
    //    while (IdxEntry != IdxHead)
    //    {
    //        LDR_DATA_TABLE_ENTRY* IdxLdrEntry = CONTAINING_RECORD(IdxEntry, LDR_DATA_TABLE_ENTRY, HashLinks);
    //
    //        printf("[Name: %ws]\n", IdxLdrEntry->BaseDllName.Buffer);
    //
    //        LIST_ENTRY* LdrHead = &IdxLdrEntry->InLoadOrderLinks;
    //        LIST_ENTRY* LdrEntry = LdrHead->Flink;
    //        while (LdrEntry != LdrHead)
    //        {
    //            LDR_DATA_TABLE_ENTRY* IdxLdrEntryMod = CONTAINING_RECORD(LdrEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    //
    //            printf("  -> [Name: %ws]\n", IdxLdrEntryMod->BaseDllName.Buffer);
    //
    //            LdrEntry = LdrEntry->Flink;
    //        }
    //
    //        IdxEntry = IdxEntry->Flink;
    //    }
    //}

    pHashIdx = (LIST_ENTRY*)&(LdrpHashTable)[(BaseNameHashValue & 0x1F)];
    BOOLEAN DllFound = FALSE;
    for (LIST_ENTRY* HashEntry = pHashIdx->Flink; HashEntry != pHashIdx; HashEntry = HashEntry->Flink)
    {
        LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)&HashEntry[-7];
        //LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(HashEntry, LDR_DATA_TABLE_ENTRY, HashLinks);

        //LDR_DATA_TABLE_ENTRY* DllEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(HashEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (BaseNameHashValue == (DllEntry->BaseNameHashValue) && ((Flags & 8) == 0 || (DllEntry->FlagGroup[0] & 1) != 0))
        {
            if (FullDllName)
            {
                DllFound = RtlEqualUnicodeString(FullDllName, &DllEntry->FullDllName, TRUE);
                if (DllFound)
                    goto DLL_FOUND;
            }
            else
            {
                if ((DllEntry->Flags & Redirected) == 0 && RtlEqualUnicodeString(BaseDllName, &DllEntry->BaseDllName, TRUE))
                {
                    DllFound = TRUE;
                DLL_FOUND:
                    DdagNode = DllEntry->DdagNode;
                    if (DdagNode->LoadCount != -1 && ((__int64)DdagNode->Modules.Flink[-4].Blink & 0x20) == 0)
                        _InterlockedIncrement(&DllEntry->ReferenceCount);

                    *pLdrEntry = DllEntry;
                    return DllFound ? STATUS_SUCCESS : STATUS_DLL_NOT_FOUND;
                }
                DllFound = FALSE;
            }
        }
    }
    return DllFound ? STATUS_SUCCESS : STATUS_DLL_NOT_FOUND;
}

BOOLEAN __fastcall LdrpIsILOnlyImage(PIMAGE_DOS_HEADER DllBase)
{
    NTSTATUS Status;
    
    UINT_PTR LastRVASection;
    PIMAGE_COR20_HEADER CorHeader;
    Status = RtlpImageDirectoryEntryToDataEx(DllBase, 1u, 0xEu, &LastRVASection, (PVOID*)&CorHeader);
    if (Status < 0)
        return Status;

    return CorHeader && LastRVASection >= 0x48 && (CorHeader->Flags & 1) != 0;
}

VOID __fastcall LdrpAddNodeServiceTag(LDR_DDAG_NODE* DdagNode, UINT_PTR ServiceTag)
{
    //LDR_DATA_TABLE_ENTRY* LdrEntry = CONTAINING_RECORD(DdagNode->Modules.Flink, LDR_DATA_TABLE_ENTRY, DdagNode);
    if (DdagNode->LoadCount != -1 && ((__int64)DdagNode->Modules.Flink[-4].Blink & 0x20) == 0)
    //if (DdagNode->LoadCount != -1 && (LdrEntry->FlagGroup[0] & 0x20) == 0)
    {
        for (LDR_SERVICE_TAG_RECORD* i = DdagNode->ServiceTagList; i; i = i->Next)
        {
            if (i->ServiceTag == ServiceTag)
                return;
        }

        LDR_SERVICE_TAG_RECORD* Heap = (LDR_SERVICE_TAG_RECORD*)RtlAllocateHeap(*LdrpHeap, 0, 0x10);
        if (Heap)
        {
            Heap->ServiceTag = ServiceTag;
            Heap->Next = DdagNode->ServiceTagList;
            DdagNode->ServiceTagList = Heap;

            SINGLE_LIST_ENTRY* Tail = DdagNode->Dependencies.Tail;
            if (Tail)
            {
                SINGLE_LIST_ENTRY* Tail_2 = Tail;
                do
                {
                    Tail_2 = Tail_2->Next;
                    // LDR_DDAG_NODE* NextNode = CONTAINING_RECORD(Tail_2, LDR_DDAG_NODE, CondenseLink);
                    LdrpAddNodeServiceTag((LDR_DDAG_NODE*)Tail_2[1].Next, ServiceTag);
                    //LdrpAddNodeServiceTag(NextNode, ServiceTag);
                } while (Tail_2 != Tail);
            }
        }
    }
}

PIMAGE_LOAD_CONFIG_DIRECTORY LdrImageDirectoryEntryToLoadConfig(PIMAGE_DOS_HEADER DllBase)
{
    NTSTATUS Status = STATUS_SUCCESS;
  
    PIMAGE_NT_HEADERS OutHeaders = nullptr;
    RtlImageNtHeaderEx(1u, DllBase, 0, &OutHeaders);
    if (!DllBase)
        return nullptr;

    UINT_PTR LastRVASection = 0;
    PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfigDirectory = nullptr;
    Status = RtlpImageDirectoryEntryToDataEx(DllBase, 1u, 0xAu, &LastRVASection, (PVOID*)&LoadConfigDirectory);
    if (!NT_SUCCESS(Status))
        return nullptr;

    if (LoadConfigDirectory && (DWORD)LastRVASection && (DWORD)LastRVASection == LoadConfigDirectory->Size && OutHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        return LoadConfigDirectory;

    return nullptr;
}

BOOLEAN __fastcall LdrpShouldModuleImportBeRedirected(LDR_DATA_TABLE_ENTRY* DllEntry)
{
    if (!DllEntry || !*LdrpRedirectionModule || *LdrpRedirectionModule == DllEntry)
        return FALSE;

    if ((NtCurrentPeb()->BitField & IsPackagedProcess) != 0)
        return DllEntry->FlagGroup[0] & PackagedBinary;

    // LdrpRedirectionCalloutFunc is a function pointer.
    if (*LdrpRedirectionCalloutFunc)
        return (*LdrpRedirectionCalloutFunc)(DllEntry->FullDllName.Buffer);
    else
        return TRUE;
}

PIMAGE_IMPORT_DESCRIPTOR __fastcall LdrpGetImportDescriptorForSnap(LDRP_LOAD_CONTEXT* LoadContext)
{
    NTSTATUS Status;

    // [CORRECT]
    //LDR_DATA_TABLE_ENTRY* DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
    LDR_DATA_TABLE_ENTRY* DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    UINT_PTR LastRVASection;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
    Status = RtlpImageDirectoryEntryToDataEx(DllEntry->DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &LastRVASection, (PVOID*)&pImageImportDescriptor);
    if (!NT_SUCCESS(Status))
        return nullptr;
    if (DllEntry == *LdrpImageEntry && (((ULONG64)(*qword_1993A8) >> 44) & 3) == 1)
    {
        PIMAGE_NT_HEADERS pImageNtHeaders = nullptr;
        RtlImageNtHeaderEx(3, DllEntry->DllBase, 0, (PIMAGE_NT_HEADERS*)&pImageNtHeaders);
        if (!((LdrpCheckPagesForTampering(&pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], 8) || LdrpCheckPagesForTampering((PIMAGE_DATA_DIRECTORY)pImageImportDescriptor, (ULONG)LastRVASection)) && NT_SUCCESS(LdrpMapCleanModuleView(LoadContext))))
        {
            return nullptr;
        }
    }
    return pImageImportDescriptor;
}

NTSTATUS __fastcall LdrpMapCleanModuleView(LDRP_LOAD_CONTEXT* LoadContext)
{
    NTSTATUS Status;

    HANDLE ProcessInformation = 0;
    PIMAGE_DOS_HEADER ImageDosHeader = nullptr;
    ULONG64 ViewSize = 0;
    if (CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) != *LdrpImageEntry)
        return STATUS_NOT_SUPPORTED;

    Status = NtQueryInformationProcess((HANDLE)-1, ProcessImageSection, &ProcessInformation, 8, 0);
    if (NT_SUCCESS(Status))
    {
        Status = ZwMapViewOfSection(ProcessInformation, (HANDLE)-1u, &ImageDosHeader, 0, 0, 0, (PULONG)&ViewSize, ViewShare, 0x40000u, 2u);
        if (NT_SUCCESS(Status))
            LoadContext->ImageBase = ImageDosHeader;

        NtClose(ProcessInformation);
    }

    return Status;
}

LDR_DATA_TABLE_ENTRY* __fastcall LdrpHandleReplacedModule(LDR_DATA_TABLE_ENTRY* LdrEntry)
{
    LDR_DATA_TABLE_ENTRY* DllEntry = LdrEntry;
    if (LdrEntry)
    {
        LDRP_LOAD_CONTEXT* LoadContext = (LDRP_LOAD_CONTEXT*)LdrEntry->LoadContext;
        if (LoadContext)
        {
            if ((LoadContext->Flags & 0x80000) == 0 && (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink != LdrEntry)
            {
                DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
                LoadContext->WorkQueueListEntry.Flink = &LdrEntry->InLoadOrderLinks;
            }
        }
    }
    return DllEntry;
}

NTSTATUS __fastcall LdrpFreeReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry)
{
    LdrpFreeLoadContext(LdrDataTableEntry->LoadContext);
    // Revokes ProcessStaticImport (0x20) flag.
    LdrDataTableEntry->Flags &= ~ProcessStaticImport;
    LdrDataTableEntry->ReferenceCount = 1;
    return LdrpDereferenceModule(LdrDataTableEntry);
}

VOID __fastcall LdrpHandlePendingModuleReplaced(LDRP_LOAD_CONTEXT* LoadContext)
{
    LDR_DATA_TABLE_ENTRY* Entry = (LDR_DATA_TABLE_ENTRY*)LoadContext->pvImports;
    if (Entry)
    {
        LDR_DATA_TABLE_ENTRY* ReturnEntry = LdrpHandleReplacedModule(Entry);
        LDR_DATA_TABLE_ENTRY** CompareEntry = LoadContext->pvImports;
        if (ReturnEntry != (LDR_DATA_TABLE_ENTRY*)CompareEntry)
            LdrpFreeReplacedModule((LDR_DATA_TABLE_ENTRY*)CompareEntry);
        LoadContext->pvImports = nullptr;
    }
}

PIMAGE_SECTION_HEADER __fastcall RtlSectionTableFromVirtualAddress(PIMAGE_NT_HEADERS NtHeader, PVOID Base, UINT_PTR Address)
{
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((char*)&NtHeader->OptionalHeader + NtHeader->FileHeader.SizeOfOptionalHeader);
    if (!NtHeader->FileHeader.NumberOfSections)
        return nullptr;

    ULONG NumberOfSections = NtHeader->FileHeader.NumberOfSections;
    ULONG SectionIdx = 0;
    while (TRUE)
    {
        ULONG VirtualAddress = SectionHeader->VirtualAddress;
        if ((unsigned int)Address >= VirtualAddress && (unsigned int)Address < SectionHeader->SizeOfRawData + VirtualAddress)
            break;

        ++SectionHeader;
        if (++SectionIdx >= NumberOfSections)
            return nullptr;
    }
    return SectionHeader;
}

PIMAGE_SECTION_HEADER __fastcall RtlAddressInSectionTable(PIMAGE_NT_HEADERS NtHeader, PVOID Base, UINT_PTR Address)
{
    PIMAGE_SECTION_HEADER SectionHeader;

    SectionHeader = RtlSectionTableFromVirtualAddress(NtHeader, Base, Address);
    if (SectionHeader)
        return (PIMAGE_SECTION_HEADER)(SectionHeader->PointerToRawData - SectionHeader->VirtualAddress);
    return SectionHeader;
}

BOOLEAN __fastcall LdrpValidateEntrySection(LDR_DATA_TABLE_ENTRY* DllEntry)
{
    PIMAGE_NT_HEADERS OutHeaders;
    RtlImageNtHeaderEx(3u, DllEntry->DllBase, 0, &OutHeaders);
    ULONG AddressOfEntryPoint = OutHeaders->OptionalHeader.AddressOfEntryPoint;
    return !AddressOfEntryPoint || !DllEntry->EntryPoint || AddressOfEntryPoint >= OutHeaders->OptionalHeader.SizeOfHeaders;
}

BOOL __fastcall LdrpIsExecutableRelocatedImage(PIMAGE_DOS_HEADER DllBase)
{
    MEMORY_IMAGE_INFORMATION MemoryInformation; // [rsp+30h] [rbp-28h] BYREF
    PIMAGE_NT_HEADERS OutHeaders; // [rsp+68h] [rbp+10h] BYREF

    return NT_SUCCESS(RtlImageNtHeaderEx(3u, DllBase, 0i64, &OutHeaders) >= 0) && (PIMAGE_DOS_HEADER)OutHeaders->OptionalHeader.ImageBase == DllBase
        && NT_SUCCESS(ZwQueryVirtualMemory((HANDLE)-1, DllBase, MemoryImageInformation, &MemoryInformation, 0x18, 0))
        && MemoryInformation.ImageBase == DllBase
        && (MemoryInformation.ImageFlags & 2) == 0
        && (MemoryInformation.ImageFlags & 1) == 0;
}

TLS_ENTRY* __fastcall LdrpFindTlsEntry(LDR_DATA_TABLE_ENTRY* LdrEntry)
{
    TLS_ENTRY* TlsEntry;

    for (TlsEntry = *LdrpTlsList; TlsEntry != (TLS_ENTRY*)LdrpTlsList; TlsEntry = (TLS_ENTRY*)TlsEntry->TlsEntry.Flink)
    {
        if ((LDR_DATA_TABLE_ENTRY*)TlsEntry->ModuleEntry == LdrEntry)
            return TlsEntry;
    }
    return nullptr;
}

BOOL __fastcall ImageTlsCallbackCaller(HINSTANCE hInstDll, DWORD fdwReason, LPVOID lpvReserved)
{
    ((void(__fastcall*)(HINSTANCE, DWORD, LPVOID))lpvReserved)(hInstDll, fdwReason, 0);
    return 1;
}

// Implemented inside LOADLIBRARY class to use WID_HIDDEN
NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpThreadTokenSetMainThreadToken() // CHECKED.
{
    NTSTATUS Status;
    
    HANDLE ReturnToken = NULL;
    Status = NtOpenThreadToken((HANDLE)-2, 0x2001C, 0, &ReturnToken);
    *LdrpMainThreadToken = ReturnToken;
    if (Status != STATUS_NO_TOKEN)
    {
        WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0xDC8, "LdrpThreadTokenSetMainThreadToken", 2, "Status: 0x%x\n", Status); )
    }
    return Status;
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpThreadTokenUnsetMainThreadToken() // CHECKED.
{
    NTSTATUS Status;

    Status = NtClose(*LdrpMainThreadToken);
    *LdrpMainThreadToken = NULL;
    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 0xDEE, "LdrpThreadTokenUnsetMainThreadToken", 2u, "Status: 0x%x\n", Status); )
    return Status;
}

LDR_DATA_TABLE_ENTRY* __fastcall WID::Loader::LOADLIBRARY::LdrpHandleReplacedModule(LDR_DATA_TABLE_ENTRY* LdrEntry) // CHECKED.
{
    LDR_DATA_TABLE_ENTRY* DllEntry = LdrEntry;
    if (LdrEntry)
    {
        LDRP_LOAD_CONTEXT* LoadContext = LdrEntry->LoadContext;
        if (LoadContext)
        {
            DllEntry = CONTAINING_RECORD(LoadContext->WorkQueueListEntry.Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            //if ((LoadContext->Flags & SEC_64K_PAGES) == 0 && (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink != LdrEntry)
            if ((LoadContext->Flags & SEC_64K_PAGES) == 0 && DllEntry != LdrEntry)
            {
                //DllEntry = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
                LoadContext->WorkQueueListEntry.Flink = &LdrEntry->InLoadOrderLinks;
            }
        }
    }
    return DllEntry;
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpFreeReplacedModule(LDR_DATA_TABLE_ENTRY* LdrEntry) // CHECKED.
{
    LdrpFreeLoadContext(LdrEntry->LoadContext);
    // Resets (sets to 0) flag ProcessStaticImport  (0x20)
    LdrEntry->Flags &= ~0x20u;

    // Might change if hidden, not touching for now.
    LdrEntry->ReferenceCount = 1;
    return LdrpDereferenceModule(LdrEntry);
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpResolveDllName(LDRP_LOAD_CONTEXT* LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer, PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, DWORD Flags) // CHECKED.
{
    NTSTATUS Status;

    PWCHAR FileName;
    UNICODE_STRING DllName;
    BOOLEAN FileNamesNotEqual = FALSE;

    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x6B9, "LdrpResolveDllName", 3u, "DLL name: %wZ\n", LoadContext); )

    // Converted goto to do-while loop.
    do
    {
        // This if will go in if call stack starts back from LoadLibraryExW with an absolute path.
        if (Flags & LOAD_LIBRARY_SEARCH_APPLICATION_DIR)
        {
            DllName = LoadContext->BaseDllName;
        }
        else
        {
            Status = LdrpGetFullPath(LoadContext, &FileNameBuffer->pFileName);
            if (!NT_SUCCESS(Status))
            {
                if (FileNamesNotEqual)
                    LdrpFreeUnicodeString(&DllName);

                WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
                return Status;
            }

            FileName = FileNameBuffer->FileName;
            DllName = FileNameBuffer->pFileName;

            FileNamesNotEqual = (FileNameBuffer->FileName != FileNameBuffer->pFileName.Buffer);
            if (FileNamesNotEqual)
            {
                FileNameBuffer->pFileName.Buffer = FileName;
                FileNameBuffer->pFileName.MaximumLength = MAX_PATH - 4;
                *FileName = 0;
                break;
            }
        }

        USHORT Length = DllName.Length;
        PWCHAR Buffer = DllName.Buffer;
        Status = LdrpAllocateUnicodeString(&DllName, DllName.Length);
        if (!NT_SUCCESS(Status))
        {
            if (FileNamesNotEqual)
                LdrpFreeUnicodeString(&DllName);

            WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
            return Status;
        }

        FileNamesNotEqual = TRUE;
        memmove(DllName.Buffer, Buffer, Length + 2);
        DllName.Length = Length;
    } while (FALSE);


    FileNameBuffer->pFileName.Length = 0;
    if (Flags & 0x10000000)
        Status = LdrpAppendUnicodeStringToFilenameBuffer(&FileNameBuffer->pFileName, LoadContext);
    else
        Status = LdrpGetNtPathFromDosPath(&DllName, FileNameBuffer);

    if (NT_SUCCESS(Status))
    {
        *FullDllName = DllName;
        LdrpGetBaseNameFromFullName(&DllName, BaseDllName);
        WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
        return Status;
    }

    NTSTATUS StatusAdded = (Status + 0x3FFFFFF1);
    //LONGLONG BitTestVar = 0x1C3000000011;
    LONGLONG BitTestVar = 0b0001'1100'0011'0000'0000'0000'0000'0000'0000'0000'0001'0001;
    if (StatusAdded <= 0x2C && (_bittest64(&BitTestVar, StatusAdded)) || Status == STATUS_DEVICE_OFF_LINE || Status == STATUS_DEVICE_NOT_READY)
    {
        WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x72D, "LdrpResolveDllName", 2, "Original status: 0x%08lx\n", Status); )
        Status = STATUS_DLL_NOT_FOUND;
    }

    if (FileNamesNotEqual)
        LdrpFreeUnicodeString(&DllName);

    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
    return Status;
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpFindDllActivationContext(LDR_DATA_TABLE_ENTRY* LdrEntry) // CHECKED.
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (*(UINT_PTR*)(*LdrpManifestProberRoutine))
    {
        PEB* PEB = NtCurrentPeb();
        if (LdrEntry != *LdrpImageEntry || !PEB->ActivationContextData)
        {
            PWCHAR Buffer = LdrEntry->FullDllName.Buffer;
            if (LdrEntry == *LdrpImageEntry && *Buffer == '\\' && Buffer[1] == '?' && Buffer[2] == '?' && Buffer[3] == '\\' && Buffer[4] && Buffer[5] == ':' && Buffer[6] == '\\')
            {
                Buffer += 4;
            }

            // LdrpManifestProberRoutine is a function pointer.
            ACTIVATION_CONTEXT* pActivationCtx = nullptr;
            Status = (*LdrpManifestProberRoutine)(LdrEntry->DllBase, Buffer, &pActivationCtx);
            if ((unsigned int)(Status + 0x3FFFFF77) <= 2 || Status == STATUS_NOT_SUPPORTED || Status == STATUS_NO_SUCH_FILE || Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_RESOURCE_LANG_NOT_FOUND)
            {
                WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 733, "LdrpFindDllActivationContext", 2u, "Probing for the manifest of DLL \"%wZ\" failed with status 0x%08lx\n", &LdrEntry->FullDllName, Status); )
                Status = STATUS_SUCCESS;
            }

            if (pActivationCtx)
            {
                if (LdrEntry->EntryPointActivationContext)
                {
                    RtlReleaseActivationContext(LdrEntry->EntryPointActivationContext);
                }

                LdrEntry->EntryPointActivationContext = pActivationCtx;
            }

            if (!NT_SUCCESS(Status))
            {
                WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrsnap.c", 0x2FA, "LdrpFindDllActivationContext", 0, "Querying the active activation context failed with status 0x%08lx\n", Status); )
            }
        }
    }
    return Status;
}

// Planning to implement them all in the future.
tNtOpenThreadToken                  NtOpenThreadToken                   = nullptr;
tNtClose                            NtClose                             = nullptr;
tRtlAllocateHeap			        RtlAllocateHeap				        = nullptr;
tRtlFreeHeap				        RtlFreeHeap					        = nullptr;
tLdrGetDllPath				        LdrGetDllPath				        = nullptr;
tRtlReleasePath				        RtlReleasePath				        = nullptr;
tRtlInitUnicodeStringEx		        RtlInitUnicodeStringEx		        = nullptr;
tRtlEnterCriticalSection	        RtlEnterCriticalSection             = nullptr;
tRtlLeaveCriticalSection            RtlLeaveCriticalSection             = nullptr;
tZwSetEvent                         ZwSetEvent                          = nullptr;
tNtOpenFile                         NtOpenFile                          = nullptr;
tLdrAppxHandleIntegrityFailure      LdrAppxHandleIntegrityFailure       = nullptr;
tNtRaiseHardError                   NtRaiseHardError                    = nullptr;
tRtlImageNtHeaderEx                 RtlImageNtHeaderEx                  = nullptr;
tRtlAcquireSRWLockExclusive         RtlAcquireSRWLockExclusive          = nullptr;
tRtlReleaseSRWLockExclusive         RtlReleaseSRWLockExclusive          = nullptr;
tRtlEqualUnicodeString              RtlEqualUnicodeString               = nullptr;
tRtlAcquirePrivilege                RtlAcquirePrivilege                 = nullptr;
tRtlReleasePrivilege                RtlReleasePrivilege                 = nullptr;
tRtlCompareUnicodeStrings           RtlCompareUnicodeStrings            = nullptr;
tRtlImageNtHeader                   RtlImageNtHeader                    = nullptr;
tRtlReleaseActivationContext        RtlReleaseActivationContext         = nullptr;
tRtlCharToInteger                   RtlCharToInteger                    = nullptr;
tRtlActivateActivationContextUnsafeFast RtlActivateActivationContextUnsafeFast = nullptr;
tRtlDeactivateActivationContextUnsafeFast RtlDeactivateActivationContextUnsafeFast = nullptr;
tRtlAcquireSRWLockShared            RtlAcquireSRWLockShared             = nullptr;
tRtlReleaseSRWLockShared            RtlReleaseSRWLockShared             = nullptr;

// Signatured
tLdrpLogInternal			                        LdrpLogInternal				            = nullptr;
tLdrpInitializeDllPath		                        LdrpInitializeDllPath		            = nullptr;
tLdrpDereferenceModule		                        LdrpDereferenceModule		            = nullptr;
tLdrpLogDllState			                        LdrpLogDllState				            = nullptr;
tLdrpPreprocessDllName		                        LdrpPreprocessDllName		            = nullptr;
tLdrpFindLoadedDllByName                            LdrpFindLoadedDllByName                 = nullptr;
tLdrpDrainWorkQueue			                        LdrpDrainWorkQueue			            = nullptr;
tLdrpFindLoadedDllByHandle	                        LdrpFindLoadedDllByHandle	            = nullptr;
tLdrpDropLastInProgressCount                        LdrpDropLastInProgressCount             = nullptr;
tLdrpQueryCurrentPatch                              LdrpQueryCurrentPatch                   = nullptr;
tLdrpUndoPatchImage                                 LdrpUndoPatchImage                      = nullptr;
tLdrpDetectDetour                                   LdrpDetectDetour                        = nullptr;
tLdrpFindOrPrepareLoadingModule                     LdrpFindOrPrepareLoadingModule          = nullptr;
tLdrpFreeLoadContext                                LdrpFreeLoadContext                     = nullptr;
tLdrpCondenseGraph                                  LdrpCondenseGraph                       = nullptr;
tLdrpBuildForwarderLink                             LdrpBuildForwarderLink                  = nullptr;
tLdrpPinModule                                      LdrpPinModule                           = nullptr;
tLdrpApplyPatchImage                                LdrpApplyPatchImage                     = nullptr;
tLdrpFreeLoadContextOfNode                          LdrpFreeLoadContextOfNode               = nullptr;
tLdrpDecrementModuleLoadCountEx                     LdrpDecrementModuleLoadCountEx          = nullptr;
tLdrpLogError                                       LdrpLogError                            = nullptr;
tLdrpLogDeprecatedDllEtwEvent                       LdrpLogDeprecatedDllEtwEvent            = nullptr;
tLdrpLogLoadFailureEtwEvent                         LdrpLogLoadFailureEtwEvent              = nullptr;
tLdrpReportError                                    LdrpReportError                         = nullptr;
tLdrpResolveDllName                                 LdrpResolveDllName                      = nullptr;
tLdrpAppCompatRedirect                              LdrpAppCompatRedirect                   = nullptr;
tLdrpHashUnicodeString                              LdrpHashUnicodeString                   = nullptr;
tLdrpFindExistingModule                             LdrpFindExistingModule                  = nullptr;
tLdrpLoadContextReplaceModule                       LdrpLoadContextReplaceModule            = nullptr;
tLdrpSearchPath                                     LdrpSearchPath                          = nullptr;
tLdrpIsSecurityEtwLoggingEnabled                    LdrpIsSecurityEtwLoggingEnabled         = nullptr;
tLdrpLogEtwDllSearchResults                         LdrpLogEtwDllSearchResults              = nullptr;
tLdrpCheckForRetryLoading                           LdrpCheckForRetryLoading                = nullptr;
tLdrpLogEtwEvent                                    LdrpLogEtwEvent                         = nullptr;
tLdrpCheckComponentOnDemandEtwEvent                 LdrpCheckComponentOnDemandEtwEvent      = nullptr;
tLdrpValidateIntegrityContinuity                    LdrpValidateIntegrityContinuity         = nullptr;
tLdrpSetModuleSigningLevel                          LdrpSetModuleSigningLevel               = nullptr;
tLdrpCodeAuthzCheckDllAllowed                       LdrpCodeAuthzCheckDllAllowed            = nullptr;
tLdrpGetFullPath                                    LdrpGetFullPath                         = nullptr;
tLdrpAllocateUnicodeString                          LdrpAllocateUnicodeString               = nullptr;
tLdrpAppendUnicodeStringToFilenameBuffer            LdrpAppendUnicodeStringToFilenameBuffer = nullptr;
tLdrpGetNtPathFromDosPath                           LdrpGetNtPathFromDosPath                = nullptr;
tLdrpFindLoadedDllByMappingLockHeld                 LdrpFindLoadedDllByMappingLockHeld      = nullptr;
tLdrpInsertDataTableEntry                           LdrpInsertDataTableEntry                = nullptr;
tLdrpInsertModuleToIndexLockHeld                    LdrpInsertModuleToIndexLockHeld         = nullptr;
tLdrpLogEtwHotPatchStatus                           LdrpLogEtwHotPatchStatus                = nullptr;
tLdrpLogNewDllLoad                                  LdrpLogNewDllLoad                       = nullptr;
tLdrpProcessMachineMismatch                         LdrpProcessMachineMismatch              = nullptr;
tRtlQueryImageFileKeyOption                         RtlQueryImageFileKeyOption              = nullptr;
tRtlpImageDirectoryEntryToDataEx                    RtlpImageDirectoryEntryToDataEx         = nullptr;
tLdrpLogDllRelocationEtwEvent                       LdrpLogDllRelocationEtwEvent            = nullptr;
tLdrpNotifyLoadOfGraph                              LdrpNotifyLoadOfGraph                   = nullptr;
tLdrpDynamicShimModule                              LdrpDynamicShimModule                   = nullptr;
tLdrpAcquireLoaderLock                              LdrpAcquireLoaderLock                   = nullptr;
tLdrpReleaseLoaderLock                              LdrpReleaseLoaderLock                   = nullptr;
tLdrpCheckPagesForTampering                         LdrpCheckPagesForTampering              = nullptr;
tLdrpLoadDependentModuleA                           LdrpLoadDependentModuleA                = nullptr;
tLdrpLoadDependentModuleW                           LdrpLoadDependentModuleW                = nullptr;
tLdrpQueueWork                                      LdrpQueueWork                           = nullptr;
tLdrpHandleTlsData                                  LdrpHandleTlsData                       = nullptr;
tLdrControlFlowGuardEnforcedWithExportSuppression   LdrControlFlowGuardEnforcedWithExportSuppression = nullptr;
tLdrpUnsuppressAddressTakenIat                      LdrpUnsuppressAddressTakenIat           = nullptr;
tLdrControlFlowGuardEnforced                        LdrControlFlowGuardEnforced             = nullptr;
tRtlpxLookupFunctionTable                           RtlpxLookupFunctionTable                = nullptr; 
tLdrpCheckRedirection                               LdrpCheckRedirection                    = nullptr;
tCompatCachepLookupCdb                              CompatCachepLookupCdb                   = nullptr;
tLdrpGenRandom                                      LdrpGenRandom                           = nullptr;
tLdrInitSecurityCookie                              LdrInitSecurityCookie                   = nullptr;
tLdrpCfgProcessLoadConfig                           LdrpCfgProcessLoadConfig                = nullptr;
tRtlInsertInvertedFunctionTable                     RtlInsertInvertedFunctionTable          = nullptr;
tLdrpSignalModuleMapped                             LdrpSignalModuleMapped                  = nullptr;
tAVrfDllLoadNotification                            AVrfDllLoadNotification                 = nullptr;
tLdrpSendDllNotifications                           LdrpSendDllNotifications                = nullptr;
tLdrpCallTlsInitializers                            LdrpCallTlsInitializers                 = nullptr;
