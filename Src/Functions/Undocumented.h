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

#define DOS_MAX_COMPONENT_LENGTH 255
#define DOS_MAX_PATH_LENGTH (DOS_MAX_COMPONENT_LENGTH + 5)

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

#define RTL_USER_PROC_CURDIR_CLOSE 0x00000002
#define RTL_USER_PROC_CURDIR_INHERIT 0x00000003

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_DRIVE_LETTER_VALID (USHORT)0x0001

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    
    ULONG Flags;
    ULONG DebugFlags;
    
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
   
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;

    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    ULONG EnvironmentSize;
    ULONG EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
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
        SINGLE_LIST_ENTRY* RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY* CondenseLink;
    ULONG PreorderNumber;
    ULONG Pad;
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
    PIMAGE_DOS_HEADER DllBase;
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

#define PROCESSOR_FEATURE_MAX 64

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union {
        ULONG SharedDataFlags;
        struct {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } DUMMYSTRUCTNAME2;
    } DUMMYUNIONNAME2;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     SystemCallPad[2];
    union {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union {
        USHORT QpcData;
        struct {
            UCHAR QpcBypassEnabled;
            UCHAR QpcShift;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;

enum DRAIN_TASK
{
    WaitLoadComplete = 0,
    WaitWorkComplete
};

typedef struct _PEB {
    BYTE                         InheritedAddressSpace;
    BYTE                         ReadImageFileExecOptions;
    BYTE                         BeingDebugged;
    union {
        UCHAR BitField;
        struct {
            /*  bit fields, follow link  */
        };
    };

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
    KUSER_SHARED_DATA*           SharedData;
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

    //Appended for Windows Server 2003
    PVOID SparePointers[4];
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG SpareUlongs[5];
    ULONG FlsHighIndex;

    //Appended for Windows Vista
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;

    //Appended for Windows 7
    PVOID pUnused;
    PVOID pImageHeaderHash;
    union {
        ULONG TracingFlags;
        struct {
            /*  bit fields, follow link  */
        };
    };
} PEB, * PPEB;

struct FUNCTION_TABLE_DATA
{
    UINT_PTR TableAddress;
    PIMAGE_DOS_HEADER ImageBase;
    DWORD ImageSize;
    DWORD Size;
};

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

enum HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore = 0x0,
    OptionOk = 0x1,
    OptionOkCancel = 0x2,
    OptionRetryCancel = 0x3,
    OptionYesNo = 0x4,
    OptionYesNoCancel = 0x5,
    OptionShutdownSystem = 0x6,
};

enum HARDERROR_RESPONSE
{
    ResponseReturnToCaller = 0x0,
    ResponseNotHandled = 0x1,
    ResponseAbort = 0x2,
    ResponseCancel = 0x3,
    ResponseIgnore = 0x4,
    ResponseNo = 0x5,
    ResponseOk = 0x6,
    ResponseRetry = 0x7,
    ResponseYes = 0x8,
};

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

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

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC, * PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_BASIC;

typedef struct _RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED
{
    SIZE_T Size;
    ULONG Format;
    RTL_ACTIVATION_CONTEXT_STACK_FRAME Frame;
    PVOID Extra1;
    PVOID Extra2;
    PVOID Extra3;
    PVOID Extra4;
} RTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED, * PRTL_CALLER_ALLOCATED_ACTIVATION_CONTEXT_STACK_FRAME_EXTENDED;

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

struct LDR_UNKSTRUCT2
{
    PUNICODE_STRING Name;
    UINT64 Status;
};

typedef struct _LDRP_LOAD_CONTEXT
{
    UNICODE_STRING BaseDllName;
    LDR_UNKSTRUCT* UnkStruct;
    HANDLE SectionHandle;
    DWORD Flags;
    NTSTATUS* pStatus;
    LDR_DATA_TABLE_ENTRY* Entry;
    _LIST_ENTRY WorkQueueListEntry;
    LDR_DATA_TABLE_ENTRY* ReplacedEntry;
    LDR_DATA_TABLE_ENTRY** pvImports;
    LDR_DATA_TABLE_ENTRY** IATCheck;
    PVOID pvIAT;
    ULONG SizeOfIAT;
    ULONG CurrentDll;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
    ULONG ImageImportDescriptorLen;
    __declspec(align(8)) ULONG OriginalIATProtect;
    PVOID GuardCFCheckFunctionPointer;
    __int64 GuardFlags;
    __int64 DllNameLenCompare;
    __int64 UnknownFunc;
    SIZE_T Size;
    __int64 UnknownPtr;
    HANDLE FileHandle;
    PIMAGE_DOS_HEADER ImageBase;
    wchar_t BaseDllNameBuffer[260];
} LDRP_LOAD_CONTEXT, *PLDRP_LOAD_CONTEXT;

struct LDRP_FILENAME_BUFFER
{
    UNICODE_STRING pFileName{};
    wchar_t FileName[128]{};
};

typedef struct _MEMORY_IMAGE_INFORMATION
{
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    union
    {
        ULONG ImageFlags;
        struct
        {
            ULONG ImagePartialMap : 1;
            ULONG ImageNotExecutable : 1;
            ULONG ImageSigningLevel : 4; // REDSTONE3
            ULONG Reserved : 26;
        };
    };
} MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

enum SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
};

/*
struct MEM_EXTENDED_PARAMETER
{
    PVOID Type;
    PHANDLE pHandle;
    HANDLE Handle;
};
*/

typedef struct _MEMORY_WORKING_SET_EX_BLOCK
{
    union
    {
        struct
        {
            ULONG_PTR Valid : 1;
            ULONG_PTR ShareCount : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared : 1;
            ULONG_PTR Node : 6;
            ULONG_PTR Locked : 1;
            ULONG_PTR LargePage : 1;
            ULONG_PTR Priority : 3;
            ULONG_PTR Reserved : 3;
            ULONG_PTR SharedOriginal : 1;
            ULONG_PTR Bad : 1;
            ULONG_PTR Win32GraphicsProtection : 4; // 19H1
#ifdef _WIN64
            ULONG_PTR ReservedUlong : 28;
#endif
        };
        struct
        {
            ULONG_PTR Valid : 1;
            ULONG_PTR Reserved0 : 14;
            ULONG_PTR Shared : 1;
            ULONG_PTR Reserved1 : 5;
            ULONG_PTR PageTable : 1;
            ULONG_PTR Location : 2;
            ULONG_PTR Priority : 3;
            ULONG_PTR ModifiedList : 1;
            ULONG_PTR Reserved2 : 2;
            ULONG_PTR SharedOriginal : 1;
            ULONG_PTR Bad : 1;
#ifdef _WIN64
            ULONG_PTR ReservedUlong : 32;
#endif
        } Invalid;
    };
} MEMORY_WORKING_SET_EX_BLOCK, * PMEMORY_WORKING_SET_EX_BLOCK;

// private
typedef struct _MEMORY_WORKING_SET_EX_INFORMATION
{
    PVOID VirtualAddress;
    union
    {
        MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
        ULONG_PTR Long;
    } u1;
} MEMORY_WORKING_SET_EX_INFORMATION, * PMEMORY_WORKING_SET_EX_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // q: UNICODE_STRING
    MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation, // since WIN11
    MemoryBadInformationAllProcesses, // since 22H1
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation,
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // 80
    ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage,
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures,
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority, // q: ULONG
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _file_info
{
    ULONG type;
    char info;
} file_info;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PVOID AssemblyArray;
} ASSEMBLY_STORAGE_MAP;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ACTIVATION_CONTEXT
{
    LONG RefCount;
    ULONG Flags;
    LIST_ENTRY Links;
    PVOID ActivationContextData;
    PVOID NotificationRoutine;
    PVOID NotificationContext;
    ULONG SentNotifications[8];
    ULONG DisabledNotifications[8];
    ASSEMBLY_STORAGE_MAP* StorageMap;
    ASSEMBLY_STORAGE_MAP_ENTRY* InlineStorageMapEntires;
    ULONG StackTraceIndex;
    PVOID StackTraces[4][4];
    file_info config;
    file_info appdir;
    char pad[256];
} ACTIVATION_CONTEXT;

#define SEC_NO_FLAGS   0x000

/* Tells the OS to allocate space for this section when loading.
This is clear for a section containing debug information
only. */
#define SEC_ALLOC      0x001

/* Tells the OS to load the section from the file when loading.
This is clear for a .bss section. */
#define SEC_LOAD       0x002

/* The section contains data still to be relocated, so there is
some relocation information too. */
#define SEC_RELOC      0x004

#if 0   /* Obsolete ? */
#define SEC_BALIGN     0x008
#endif

/* A signal to the OS that the section contains read only
data. */
#define SEC_READONLY   0x010

/* The section contains code only. */
#define SEC_CODE       0x020

/* The section contains data only. */
#define SEC_DATA       0x040

/* The section will reside in ROM. */
#define SEC_ROM        0x080

/* The section contains constructor information. This section
type is used by the linker to create lists of constructors and
destructors used by g++. When a back end sees a symbol
which should be used in a constructor list, it creates a new
section for the type of name (e.g., __CTOR_LIST__), attaches
the symbol to it, and builds a relocation. To build the lists
of constructors, all the linker has to do is catenate all the
sections called __CTOR_LIST__ and relocate the data
contained within - exactly the operations it would peform on
standard data. */
#define SEC_CONSTRUCTOR 0x100

/* The section is a constuctor, and should be placed at the
end of the text, data, or bss section(?). */
#define SEC_CONSTRUCTOR_TEXT 0x1100
#define SEC_CONSTRUCTOR_DATA 0x2100
#define SEC_CONSTRUCTOR_BSS  0x3100

/* The section has contents - a data section could be
SEC_ALLOC | SEC_HAS_CONTENTS; a debug section could be
SEC_HAS_CONTENTS */
#define SEC_HAS_CONTENTS 0x200

/* An instruction to the linker to not output the section
even if it has information which would normally be written. */
#define SEC_NEVER_LOAD 0x400

/* The section is a COFF shared library section.  This flag is
only for the linker.  If this type of section appears in
the input file, the linker must copy it to the output file
without changing the vma or size.  FIXME: Although this
was originally intended to be general, it really is COFF
specific (and the flag was renamed to indicate this).  It
might be cleaner to have some more general mechanism to
allow the back end to control what the linker does with
sections. */
#define SEC_COFF_SHARED_LIBRARY 0x800

/* The section contains common symbols (symbols may be defined
multiple times, the value of a symbol is the amount of
space it requires, and the largest symbol value is the one
used).  Most targets have exactly one of these (which we
translate to bfd_com_section_ptr), but ECOFF has two. */
#define SEC_IS_COMMON 0x8000

/* The section contains only debugging information.  For
example, this is set for ELF .debug and .stab sections.
strip tests this flag to see if a section can be
discarded. */
#define SEC_DEBUGGING 0x10000

/* The contents of this section are held in memory pointed to
by the contents field.  This is checked by
bfd_get_section_contents, and the data is retrieved from
memory if appropriate.  */
#define SEC_IN_MEMORY 0x20000

/* The contents of this section are to be excluded by the
linker for executable and shared objects unless those
objects are to be further relocated.  */
#define SEC_EXCLUDE 0x40000

/* The contents of this section are to be sorted by the
based on the address specified in the associated symbol
table.  */
#define SEC_SORT_ENTRIES 0x80000

/* When linking, duplicate sections of the same name should be
discarded, rather than being combined into a single section as
is usually done.  This is similar to how common symbols are
handled.  See SEC_LINK_DUPLICATES below.  */
#define SEC_LINK_ONCE 0x100000

/* If SEC_LINK_ONCE is set, this bitfield describes how the linker
should handle duplicate sections.  */
#define SEC_LINK_DUPLICATES 0x600000

/* This value for SEC_LINK_DUPLICATES means that duplicate
sections with the same name should simply be discarded. */
#define SEC_LINK_DUPLICATES_DISCARD 0x0

/* This value for SEC_LINK_DUPLICATES means that the linker
should warn if there are any duplicate sections, although
it should still only link one copy.  */
#define SEC_LINK_DUPLICATES_ONE_ONLY 0x200000

/* This value for SEC_LINK_DUPLICATES means that the linker
should warn if any duplicate sections are a different size.  */
#define SEC_LINK_DUPLICATES_SAME_SIZE 0x400000

/* This value for SEC_LINK_DUPLICATES means that the linker
should warn if any duplicate sections contain different
contents.  */
#define SEC_LINK_DUPLICATES_SAME_CONTENTS 0x600000

/* This section was created by the linker as part of dynamic
relocation or other arcane processing.  It is skipped when
going through the first-pass output, trusting that someone
else up the line will take care of it later.  */
#define SEC_LINKER_CREATED 0x800000