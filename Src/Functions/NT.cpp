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

// Functions
PEB* NtCurrentPeb()
{
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer)
{
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
}

VOID __fastcall RtlFreeUnicodeString(PUNICODE_STRING UnicodeString)
{
    WCHAR* Buffer; // rcx

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

ULONG __fastcall RtlGetCurrentServiceSessionId(VOID)
{
    KUSER_SHARED_DATA* SharedData; // rax

    SharedData = NtCurrentPeb()->SharedData;

    // I highly doubt it's TickCountLowDeprecated but anyways.
    if (SharedData)
        SharedData = (KUSER_SHARED_DATA*)SharedData->TickCountLowDeprecated;
    return (ULONG)SharedData;
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

// Implemented inside LOADLIBRARY class to use WID_HIDDEN
NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpThreadTokenSetMainThreadToken()
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

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpThreadTokenUnsetMainThreadToken()
{
    NTSTATUS Status;

    Status = NtClose(*LdrpMainThreadToken);
    *LdrpMainThreadToken = NULL;
    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrapi.c", 3566, "LdrpThreadTokenUnsetMainThreadToken", 2u, "Status: 0x%x\n", Status); )
    return Status;
}

LDR_DATA_TABLE_ENTRY* __fastcall WID::Loader::LOADLIBRARY::LdrpHandleReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry)
{
    LDR_DATA_TABLE_ENTRY* Return;

    Return = LdrDataTableEntry;
    if (LdrDataTableEntry)
    {
        LDRP_LOAD_CONTEXT* LoadContext = (LDRP_LOAD_CONTEXT*)LdrDataTableEntry->LoadContext;
        if (LoadContext)
        {
            if ((LoadContext->Flags & SEC_64K_PAGES) == 0 && (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink != LdrDataTableEntry)
            {
                Return = (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink;
                LoadContext->WorkQueueListEntry.Flink = &LdrDataTableEntry->InLoadOrderLinks;
            }
        }
    }
    return Return;
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpFreeReplacedModule(LDR_DATA_TABLE_ENTRY* LdrDataTableEntry)
{
    LdrpFreeLoadContext(LdrDataTableEntry->LoadContext);
    // Resets (sets to 0) flag ProcessStaticImport  (0x20)
    LdrDataTableEntry->Flags &= ~0x20u;

    // Might change if hidden, not touching for now.
    LdrDataTableEntry->ReferenceCount = 1;
    return LdrpDereferenceModule(LdrDataTableEntry);
}

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpResolveDllName(LDRP_LOAD_CONTEXT* LoadContext, LDRP_FILENAME_BUFFER* FileNameBuffer, PUNICODE_STRING BaseDllName, PUNICODE_STRING FullDllName, DWORD Flags)
{
    NTSTATUS Status;

    PWCHAR FileName;
    UNICODE_STRING DllName;
    BOOLEAN ResolvedNamesNotEqual = FALSE;

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
                if (ResolvedNamesNotEqual)
                    LdrpFreeUnicodeString(&DllName);

                WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
                return Status;
            }

            FileName = FileNameBuffer->FileName;
            DllName = FileNameBuffer->pFileName;

            ResolvedNamesNotEqual = (FileNameBuffer->FileName != FileNameBuffer->pFileName.Buffer);
            if (ResolvedNamesNotEqual)
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
            if (ResolvedNamesNotEqual)
                LdrpFreeUnicodeString(&DllName);

            WID_HIDDEN(LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
            return Status;
        }
        ResolvedNamesNotEqual = 1;
        memmove(DllName.Buffer, Buffer, Length + 2);
        DllName.Length = Length;
    } while (FALSE);


    FileNameBuffer->pFileName.Length = 0;
    if ((Flags & 0x10000000) != 0)
        Status = LdrpAppendUnicodeStringToFilenameBuffer(&FileNameBuffer->pFileName.Length, LoadContext);
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
    if (ResolvedNamesNotEqual)
        LdrpFreeUnicodeString(&DllName);

    WID_HIDDEN( LdrpLogInternal("minkernel\\ntdll\\ldrfind.c", 0x742, "LdrpResolveDllName", 4, "Status: 0x%08lx\n", Status); )
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

// Signatured
tLdrpLogInternal			                LdrpLogInternal				            = nullptr;
tLdrpInitializeDllPath		                LdrpInitializeDllPath		            = nullptr;
tLdrpDereferenceModule		                LdrpDereferenceModule		            = nullptr;
tLdrpLogDllState			                LdrpLogDllState				            = nullptr;
tLdrpPreprocessDllName		                LdrpPreprocessDllName		            = nullptr;
tLdrpFastpthReloadedDll		                LdrpFastpthReloadedDll		            = nullptr;
tLdrpDrainWorkQueue			                LdrpDrainWorkQueue			            = nullptr;
tLdrpFindLoadedDllByHandle	                LdrpFindLoadedDllByHandle	            = nullptr;
tLdrpDropLastInProgressCount                LdrpDropLastInProgressCount             = nullptr;
tLdrpQueryCurrentPatch                      LdrpQueryCurrentPatch                   = nullptr;
tLdrpUndoPatchImage                         LdrpUndoPatchImage                      = nullptr;
tLdrpDetectDetour                           LdrpDetectDetour                        = nullptr;
tLdrpFindOrPrepareLoadingModule             LdrpFindOrPrepareLoadingModule          = nullptr;
tLdrpFreeLoadContext                        LdrpFreeLoadContext                     = nullptr;
tLdrpCondenseGraph                          LdrpCondenseGraph                       = nullptr;
tLdrpBuildForwarderLink                     LdrpBuildForwarderLink                  = nullptr;
tLdrpPinModule                              LdrpPinModule                           = nullptr;
tLdrpApplyPatchImage                        LdrpApplyPatchImage                     = nullptr;
tLdrpFreeLoadContextOfNode                  LdrpFreeLoadContextOfNode               = nullptr;
tLdrpDecrementModuleLoadCountEx             LdrpDecrementModuleLoadCountEx          = nullptr;
tLdrpLogError                               LdrpLogError                            = nullptr;
tLdrpLogDeprecatedDllEtwEvent               LdrpLogDeprecatedDllEtwEvent            = nullptr;
tLdrpLogLoadFailureEtwEvent                 LdrpLogLoadFailureEtwEvent              = nullptr;
tLdrpReportError                            LdrpReportError                         = nullptr;
tLdrpResolveDllName                         LdrpResolveDllName                      = nullptr;
tLdrpAppCompatRedirect                      LdrpAppCompatRedirect                   = nullptr;
tLdrpHashUnicodeString                      LdrpHashUnicodeString                   = nullptr;
tLdrpFindExistingModule                     LdrpFindExistingModule                  = nullptr;
tLdrpLoadContextReplaceModule               LdrpLoadContextReplaceModule            = nullptr;
tLdrpCheckForRetryLoading                   LdrpCheckForRetryLoading                = nullptr;
tLdrpLogEtwEvent                            LdrpLogEtwEvent                         = nullptr;
tLdrpCheckComponentOnDemandEtwEvent         LdrpCheckComponentOnDemandEtwEvent      = nullptr;
tLdrpValidateIntegrityContinuity            LdrpValidateIntegrityContinuity         = nullptr;
tLdrpSetModuleSigningLevel                  LdrpSetModuleSigningLevel               = nullptr;
tLdrpCodeAuthzCheckDllAllowed               LdrpCodeAuthzCheckDllAllowed            = nullptr;
tLdrpGetFullPath                            LdrpGetFullPath                         = nullptr;
tLdrpAllocateUnicodeString                  LdrpAllocateUnicodeString               = nullptr;
tLdrpAppendUnicodeStringToFilenameBuffer    LdrpAppendUnicodeStringToFilenameBuffer = nullptr;
tLdrpGetNtPathFromDosPath                   LdrpGetNtPathFromDosPath                = nullptr;
tLdrpFindLoadedDllByNameLockHeld            LdrpFindLoadedDllByNameLockHeld         = nullptr;
tLdrpFindLoadedDllByMappingLockHeld         LdrpFindLoadedDllByMappingLockHeld      = nullptr;
tLdrpInsertDataTableEntry                   LdrpInsertDataTableEntry                = nullptr;
tLdrpInsertModuleToIndexLockHeld            LdrpInsertModuleToIndexLockHeld         = nullptr;
tLdrpLogEtwHotPatchStatus                   LdrpLogEtwHotPatchStatus                = nullptr;
tLdrpLogNewDllLoad                          LdrpLogNewDllLoad                       = nullptr;
tLdrpProcessMachineMismatch                 LdrpProcessMachineMismatch              = nullptr;
tRtlQueryImageFileKeyOption                 RtlQueryImageFileKeyOption              = nullptr;