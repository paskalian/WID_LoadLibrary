#pragma once

#include "..\Includes.h"

typedef void* PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOL       Initialized;
    LPVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
    );

typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x4
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x8
            UCHAR Balance : 2;                                                //0x8
        };
        ULONG ParentValue;                                                  //0x8
    };
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

// symbols
typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

// symbols
typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

// symbols
typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

// symbols
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

// rev
typedef struct _LDR_DEPENDENCY_RECORD
{
    SINGLE_LIST_ENTRY DependencyLink;
    PLDR_DDAG_NODE DependencyNode;
    SINGLE_LIST_ENTRY IncomingDependencyLink;
    PLDR_DDAG_NODE IncomingDependencyNode;
} LDR_DEPENDENCY_RECORD, * PLDR_DEPENDENCY_RECORD;

// symbols
typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_HOT_PATCH_STATE
{
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

// LDR_DATA_TABLE_ENTRY->Flags
#define LDRP_PACKAGED_BINARY 0x00000001
#define LDRP_MARKED_FOR_REMOVAL 0x00000002
#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_LOAD_NOTIFICATIONS_SENT 0x00000008
#define LDRP_TELEMETRY_ENTRY_PROCESSED 0x00000010
#define LDRP_PROCESS_STATIC_IMPORT 0x00000020
#define LDRP_IN_LEGACY_LISTS 0x00000040
#define LDRP_IN_INDEXES 0x00000080
#define LDRP_SHIM_DLL 0x00000100
#define LDRP_IN_EXCEPTION_TABLE 0x00000200
#define LDRP_LOAD_IN_PROGRESS 0x00001000
#define LDRP_LOAD_CONFIG_PROCESSED 0x00002000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROTECT_DELAY_LOAD 0x00008000
#define LDRP_DONT_CALL_FOR_THREADS 0x00040000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000
#define LDRP_PROCESS_ATTACH_FAILED 0x00100000
#define LDRP_COR_DEFERRED_VALIDATE 0x00200000
#define LDRP_COR_IMAGE 0x00400000
#define LDRP_DONT_RELOCATE 0x00800000
#define LDRP_COR_IL_ONLY 0x01000000
#define LDRP_CHPE_IMAGE 0x02000000
#define LDRP_CHPE_EMULATOR_IMAGE 0x04000000
#define LDRP_REDIRECTED 0x10000000
#define LDRP_COMPAT_DATABASE_PROCESSED 0x80000000

#define LDR_DATA_TABLE_ENTRY_SIZE_WINXP FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, DdagNode)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN7 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, BaseNameHashValue)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN8 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, ImplicitPathOptions)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN10 FIELD_OFFSET(LDR_DATA_TABLE_ENTRY, SigningLevel)
#define LDR_DATA_TABLE_ENTRY_SIZE_WIN11 sizeof(LDR_DATA_TABLE_ENTRY)

// symbols
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason; // since WIN8
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum; // since 22H1
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                         InheritedAddressSpace;
    BYTE                         ReadImageFileExecOptions;
    BYTE                         BeingDebugged;
    BYTE                         _SYSTEM_DEPENDENT_01;

    LPVOID                       Mutant;
    LPVOID                       ImageBaseAddress;

    PPEB_LDR_DATA                Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    LPVOID                       SubSystemData;
    LPVOID                       ProcessHeap;
    LPVOID                       FastPebLock;
    LPVOID                       _SYSTEM_DEPENDENT_02;
    LPVOID                       _SYSTEM_DEPENDENT_03;
    LPVOID                       _SYSTEM_DEPENDENT_04;
    union {
        LPVOID                     KernelCallbackTable;
        LPVOID                     UserSharedInfoPtr;
    };
    DWORD                        SystemReserved;
    DWORD                        _SYSTEM_DEPENDENT_05;
    LPVOID                       _SYSTEM_DEPENDENT_06;
    LPVOID                       TlsExpansionCounter;
    LPVOID                       TlsBitmap;
    DWORD                        TlsBitmapBits[2];
    LPVOID                       ReadOnlySharedMemoryBase;
    LPVOID                       _SYSTEM_DEPENDENT_07;
    LPVOID                       ReadOnlyStaticServerData;
    LPVOID                       AnsiCodePageData;
    LPVOID                       OemCodePageData;
    LPVOID                       UnicodeCaseTableData;
    DWORD                        NumberOfProcessors;
    union
    {
        DWORD                      NtGlobalFlag;
        LPVOID                     dummy02;
    };
    LARGE_INTEGER                CriticalSectionTimeout;
    LPVOID                       HeapSegmentReserve;
    LPVOID                       HeapSegmentCommit;
    LPVOID                       HeapDeCommitTotalFreeThreshold;
    LPVOID                       HeapDeCommitFreeBlockThreshold;
    DWORD                        NumberOfHeaps;
    DWORD                        MaximumNumberOfHeaps;
    LPVOID                       ProcessHeaps;
    LPVOID                       GdiSharedHandleTable;
    LPVOID                       ProcessStarterHelper;
    LPVOID                       GdiDCAttributeList;
    LPVOID                       LoaderLock;
    DWORD                        OSMajorVersion;
    DWORD                        OSMinorVersion;
    WORD                         OSBuildNumber;
    WORD                         OSCSDVersion;
    DWORD                        OSPlatformId;
    DWORD                        ImageSubsystem;
    DWORD                        ImageSubsystemMajorVersion;
    LPVOID                       ImageSubsystemMinorVersion;
    union
    {
        LPVOID                     ImageProcessAffinityMask;
        LPVOID                     ActiveProcessAffinityMask;
    };
#ifdef _WIN64
    LPVOID                       GdiHandleBuffer[64];
#else
    LPVOID                       GdiHandleBuffer[32];
#endif  
    LPVOID                       PostProcessInitRoutine;
    LPVOID                       TlsExpansionBitmap;
    DWORD                        TlsExpansionBitmapBits[32];
    LPVOID                       SessionId;
    ULARGE_INTEGER               AppCompatFlags;
    ULARGE_INTEGER               AppCompatFlagsUser;
    LPVOID                       pShimData;
    LPVOID                       AppCompatInfo;
    PUNICODE_STRING              CSDVersion;
    LPVOID                       ActivationContextData;
    LPVOID                       ProcessAssemblyStorageMap;
    LPVOID                       SystemDefaultActivationContextData;
    LPVOID                       SystemAssemblyStorageMap;
    LPVOID                       MinimumStackCommit;
} PEB, * PPEB;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
typedef struct _TEB_ACTIVE_FRAME* PTEB_ACTIVE_FRAME;
typedef struct _TEB_ACTIVE_FRAME_CONTEXT* PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME Previous;
    PACTIVATION_CONTEXT* ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;
#define GDI_BATCH_BUFFER_SIZE 310

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME
{
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

#if !defined(_MSC_VER)
typedef struct _PROCESSOR_NUMBER {
    USHORT Group;
    UCHAR  Number;
    UCHAR  Reserved;
} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;
#endif

typedef struct _TEB
{
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;
    PVOID ActivationContextStackPointer;
#ifdef _M_X64
    UCHAR SpareBytes[24];
#else
    UCHAR SpareBytes[36];
#endif
    ULONG TxFsContext;

    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];

    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#ifdef _M_X64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID EtwLocalData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR SoftPatchPtr1;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _M_X64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT SpareSameTebBits : 4;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    ULONG SpareUlong0;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
} TEB, * PTEB;


struct LDR_UNKSTRUCT
{
    PWCHAR pInitNameMaybe;
    __int64 field_8;
    __int64 field_10;
    int Flags;
    PWSTR pDllName;
    char Pad1[84];
    BOOLEAN IsInitedMaybe;
    char Pad2[3];
};

typedef struct _LDRP_LOAD_CONTEXT
{
    UNICODE_STRING BaseDllName;
    LDR_UNKSTRUCT* UnkStruct;
    ULONG Unknown;
    __int64 Flags;
    NTSTATUS* pStatus;
    LDR_DATA_TABLE_ENTRY* Entry;
    _LIST_ENTRY WorkQueueListEntry;
    LDR_DATA_TABLE_ENTRY* ReplacedEntry;
    LDR_DATA_TABLE_ENTRY** pvImports;
    ULONG ImportDllCount;
    LONG TaskCount;
    PVOID pvIAT;
    ULONG SizeOfIAT;
    ULONG CurrentDll;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
    ULONG ImageImportDescriptorLen;
    __declspec(align(8)) ULONG OriginalIATProtect;
    PVOID GuardCFCheckFunctionPointer;
    __int64 GuardFlags;
    __int64 DllNameLenCompare;
    char Pad0[16];
    __int64 UnknownPtr;
    __int64 Handle;
    char Pad1[8];
    wchar_t BaseDllNameBuffer[260];
} LDRP_LOAD_CONTEXT, *PLDRP_LOAD_CONTEXT;