#include "NT.h"

// Implemented.
HANDLE* LdrpMainThreadToken = nullptr;
DWORD* LdrInitState;

PEB* NtCurrentPeb()
{
	return NtCurrentTeb()->ProcessEnvironmentBlock;
}

VOID __fastcall NtdllpFreeStringRoutine(PWCH Buffer)
{
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Buffer);
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

NTSTATUS __fastcall WID::Loader::LOADLIBRARY::LdrpThreadTokenSetMainThreadToken()
{
    NTSTATUS Status;
    
    HANDLE ReturnToken = nullptr;
    Status = NtOpenThreadToken((HANDLE)-2u, 0x2001C, 0, &ReturnToken);
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
            if ((LoadContext->Flags & 0x80000) == 0 && (LDR_DATA_TABLE_ENTRY*)LoadContext->WorkQueueListEntry.Flink != LdrDataTableEntry)
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

// Planning to implement them all in the future.
tNtOpenThreadToken              NtOpenThreadToken               = nullptr;
tNtClose                        NtClose                         = nullptr;
tRtlAllocateHeap			    RtlAllocateHeap				    = nullptr;
tRtlFreeHeap				    RtlFreeHeap					    = nullptr;
tRtlFreeUnicodeString		    RtlFreeUnicodeString		    = nullptr;
tLdrGetDllPath				    LdrGetDllPath				    = nullptr;
tRtlReleasePath				    RtlReleasePath				    = nullptr;
tRtlInitUnicodeStringEx		    RtlInitUnicodeStringEx		    = nullptr;
tLdrpLogInternal			    LdrpLogInternal				    = nullptr;
tLdrpInitializeDllPath		    LdrpInitializeDllPath		    = nullptr;
tLdrpDereferenceModule		    LdrpDereferenceModule		    = nullptr;
tLdrpLogDllState			    LdrpLogDllState				    = nullptr;
tLdrpPreprocessDllName		    LdrpPreprocessDllName		    = nullptr;
tLdrpFastpthReloadedDll		    LdrpFastpthReloadedDll		    = nullptr;
tLdrpDrainWorkQueue			    LdrpDrainWorkQueue			    = nullptr;
tLdrpFindLoadedDllByHandle	    LdrpFindLoadedDllByHandle	    = nullptr;
tLdrpDropLastInProgressCount    LdrpDropLastInProgressCount     = nullptr;
tLdrpQueryCurrentPatch          LdrpQueryCurrentPatch           = nullptr;
tLdrpUndoPatchImage             LdrpUndoPatchImage              = nullptr;
tLdrpDetectDetour               LdrpDetectDetour                = nullptr;
tLdrpFindOrPrepareLoadingModule LdrpFindOrPrepareLoadingModule  = nullptr;
tLdrpFreeLoadContext            LdrpFreeLoadContext             = nullptr;
tLdrpCondenseGraph              LdrpCondenseGraph               = nullptr;
tLdrpBuildForwarderLink         LdrpBuildForwarderLink          = nullptr;
tLdrpPinModule                  LdrpPinModule                   = nullptr;
tLdrpApplyPatchImage            LdrpApplyPatchImage             = nullptr;
tLdrpFreeLoadContextOfNode      LdrpFreeLoadContextOfNode       = nullptr;
tLdrpDecrementModuleLoadCountEx LdrpDecrementModuleLoadCountEx  = nullptr;