#pragma once
#include <windows.h>
typedef struct _STRING32 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONG  Buffer;
} STRING32;
typedef struct _STRING64 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONGLONG  Buffer;
} STRING64;
// 0x8 bytes (sizeof)
struct _CLIENT_ID32 {
  ULONG UniqueProcess;  // 0x0
  ULONG UniqueThread;   // 0x4
};
// 0x10 bytes (sizeof)
struct _CLIENT_ID64 {
  ULONGLONG UniqueProcess;  // 0x0
  ULONGLONG UniqueThread;   // 0x8
};
// 0x4e0 bytes (sizeof)
struct _GDI_TEB_BATCH32 {
  ULONG Offset;       // 0x0
  ULONG HDC;          // 0x4
  ULONG Buffer[310];  // 0x8
};
// 0x4e8 bytes (sizeof)
struct _GDI_TEB_BATCH64 {
  ULONG Offset;       // 0x0
  ULONGLONG HDC;      // 0x8
  ULONG Buffer[310];  // 0x10
};
// 0xfe4 bytes (sizeof)
typedef struct _TEB32 {
  struct _NT_TIB32 NtTib;                // 0x0
  ULONG EnvironmentPointer;              // 0x1c
  struct _CLIENT_ID32 ClientId;          // 0x20
  ULONG ActiveRpcHandle;                 // 0x28
  ULONG ThreadLocalStoragePointer;       // 0x2c
  ULONG ProcessEnvironmentBlock;         // 0x30
  ULONG LastErrorValue;                  // 0x34
  ULONG CountOfOwnedCriticalSections;    // 0x38
  ULONG CsrClientThread;                 // 0x3c
  ULONG Win32ThreadInfo;                 // 0x40
  ULONG User32Reserved[26];              // 0x44
  ULONG UserReserved[5];                 // 0xac
  ULONG WOW32Reserved;                   // 0xc0
  ULONG CurrentLocale;                   // 0xc4
  ULONG FpSoftwareStatusRegister;        // 0xc8
  ULONG SystemReserved1[54];             // 0xcc
  LONG ExceptionCode;                    // 0x1a4
  ULONG ActivationContextStackPointer;   // 0x1a8
  UCHAR SpareBytes[36];                  // 0x1ac
  ULONG TxFsContext;                     // 0x1d0
  struct _GDI_TEB_BATCH32 GdiTebBatch;   // 0x1d4
  struct _CLIENT_ID32 RealClientId;      // 0x6b4
  ULONG GdiCachedProcessHandle;          // 0x6bc
  ULONG GdiClientPID;                    // 0x6c0
  ULONG GdiClientTID;                    // 0x6c4
  ULONG GdiThreadLocalInfo;              // 0x6c8
  ULONG Win32ClientInfo[62];             // 0x6cc
  ULONG glDispatchTable[233];            // 0x7c4
  ULONG glReserved1[29];                 // 0xb68
  ULONG glReserved2;                     // 0xbdc
  ULONG glSectionInfo;                   // 0xbe0
  ULONG glSection;                       // 0xbe4
  ULONG glTable;                         // 0xbe8
  ULONG glCurrentRC;                     // 0xbec
  ULONG glContext;                       // 0xbf0
  ULONG LastStatusValue;                 // 0xbf4
  struct _STRING32 StaticUnicodeString;  // 0xbf8
  WCHAR StaticUnicodeBuffer[261];        // 0xc00
  ULONG DeallocationStack;               // 0xe0c
  ULONG TlsSlots[64];                    // 0xe10
  struct LIST_ENTRY32 TlsLinks;          // 0xf10
  ULONG Vdm;                             // 0xf18
  ULONG ReservedForNtRpc;                // 0xf1c
  ULONG DbgSsReserved[2];                // 0xf20
  ULONG HardErrorMode;                   // 0xf28
  ULONG Instrumentation[9];              // 0xf2c
  struct _GUID ActivityId;               // 0xf50
  ULONG SubProcessTag;                   // 0xf60
  ULONG EtwLocalData;                    // 0xf64
  ULONG EtwTraceData;                    // 0xf68
  ULONG WinSockData;                     // 0xf6c
  ULONG GdiBatchCount;                   // 0xf70
  union {
    struct _PROCESSOR_NUMBER CurrentIdealProcessor;  // 0xf74
    ULONG IdealProcessorValue;                       // 0xf74
    struct {
      UCHAR ReservedPad0;    // 0xf74
      UCHAR ReservedPad1;    // 0xf75
      UCHAR ReservedPad2;    // 0xf76
      UCHAR IdealProcessor;  // 0xf77
    };
  };
  ULONG GuaranteedStackBytes;      // 0xf78
  ULONG ReservedForPerf;           // 0xf7c
  ULONG ReservedForOle;            // 0xf80
  ULONG WaitingOnLoaderLock;       // 0xf84
  ULONG SavedPriorityState;        // 0xf88
  ULONG SoftPatchPtr1;             // 0xf8c
  ULONG ThreadPoolData;            // 0xf90
  ULONG TlsExpansionSlots;         // 0xf94
  ULONG MuiGeneration;             // 0xf98
  ULONG IsImpersonating;           // 0xf9c
  ULONG NlsCache;                  // 0xfa0
  ULONG pShimData;                 // 0xfa4
  ULONG HeapVirtualAffinity;       // 0xfa8
  ULONG CurrentTransactionHandle;  // 0xfac
  ULONG ActiveFrame;               // 0xfb0
  ULONG FlsData;                   // 0xfb4
  ULONG PreferredLanguages;        // 0xfb8
  ULONG UserPrefLanguages;         // 0xfbc
  ULONG MergedPrefLanguages;       // 0xfc0
  ULONG MuiImpersonation;          // 0xfc4
  union {
    volatile USHORT CrossTebFlags;  // 0xfc8
    USHORT SpareCrossTebBits : 16;  // 0xfc8
  };
  union {
    USHORT SameTebFlags;  // 0xfca
    struct {
      USHORT SafeThunkCall : 1;         // 0xfca
      USHORT InDebugPrint : 1;          // 0xfca
      USHORT HasFiberData : 1;          // 0xfca
      USHORT SkipThreadAttach : 1;      // 0xfca
      USHORT WerInShipAssertCode : 1;   // 0xfca
      USHORT RanProcessInit : 1;        // 0xfca
      USHORT ClonedThread : 1;          // 0xfca
      USHORT SuppressDebugMsg : 1;      // 0xfca
      USHORT DisableUserStackWalk : 1;  // 0xfca
      USHORT RtlExceptionAttached : 1;  // 0xfca
      USHORT InitialThread : 1;         // 0xfca
      USHORT SpareSameTebBits : 5;      // 0xfca
    }SameTebFlagStruct;
  };
  ULONG TxnScopeEnterCallback;  // 0xfcc
  ULONG TxnScopeExitCallback;   // 0xfd0
  ULONG TxnScopeContext;        // 0xfd4
  ULONG LockCount;              // 0xfd8
  ULONG SpareUlong0;            // 0xfdc
  ULONG ResourceRetValue;       // 0xfe0
}TEB32;

// 0x1818 bytes (sizeof)
typedef struct _TEB64 {
  struct _NT_TIB64 NtTib;                   // 0x0
  ULONGLONG EnvironmentPointer;             // 0x38
  struct _CLIENT_ID64 ClientId;             // 0x40
  ULONGLONG ActiveRpcHandle;                // 0x50
  ULONGLONG ThreadLocalStoragePointer;      // 0x58
  ULONGLONG ProcessEnvironmentBlock;        // 0x60
  ULONG LastErrorValue;                     // 0x68
  ULONG CountOfOwnedCriticalSections;       // 0x6c
  ULONGLONG CsrClientThread;                // 0x70
  ULONGLONG Win32ThreadInfo;                // 0x78
  ULONG User32Reserved[26];                 // 0x80
  ULONG UserReserved[5];                    // 0xe8
  ULONGLONG WOW32Reserved;                  // 0x100
  ULONG CurrentLocale;                      // 0x108
  ULONG FpSoftwareStatusRegister;           // 0x10c
  ULONGLONG SystemReserved1[54];            // 0x110
  LONG ExceptionCode;                       // 0x2c0
  ULONGLONG ActivationContextStackPointer;  // 0x2c8
  UCHAR SpareBytes[24];                     // 0x2d0
  ULONG TxFsContext;                        // 0x2e8
  struct _GDI_TEB_BATCH64 GdiTebBatch;      // 0x2f0
  struct _CLIENT_ID64 RealClientId;         // 0x7d8
  ULONGLONG GdiCachedProcessHandle;         // 0x7e8
  ULONG GdiClientPID;                       // 0x7f0
  ULONG GdiClientTID;                       // 0x7f4
  ULONGLONG GdiThreadLocalInfo;             // 0x7f8
  ULONGLONG Win32ClientInfo[62];            // 0x800
  ULONGLONG glDispatchTable[233];           // 0x9f0
  ULONGLONG glReserved1[29];                // 0x1138
  ULONGLONG glReserved2;                    // 0x1220
  ULONGLONG glSectionInfo;                  // 0x1228
  ULONGLONG glSection;                      // 0x1230
  ULONGLONG glTable;                        // 0x1238
  ULONGLONG glCurrentRC;                    // 0x1240
  ULONGLONG glContext;                      // 0x1248
  ULONG LastStatusValue;                    // 0x1250
  struct _STRING64 StaticUnicodeString;     // 0x1258
  WCHAR StaticUnicodeBuffer[261];           // 0x1268
  ULONGLONG DeallocationStack;              // 0x1478
  ULONGLONG TlsSlots[64];                   // 0x1480
  struct LIST_ENTRY64 TlsLinks;             // 0x1680
  ULONGLONG Vdm;                            // 0x1690
  ULONGLONG ReservedForNtRpc;               // 0x1698
  ULONGLONG DbgSsReserved[2];               // 0x16a0
  ULONG HardErrorMode;                      // 0x16b0
  ULONGLONG Instrumentation[11];            // 0x16b8
  struct _GUID ActivityId;                  // 0x1710
  ULONGLONG SubProcessTag;                  // 0x1720
  ULONGLONG EtwLocalData;                   // 0x1728
  ULONGLONG EtwTraceData;                   // 0x1730
  ULONGLONG WinSockData;                    // 0x1738
  ULONG GdiBatchCount;                      // 0x1740
  union {
    struct _PROCESSOR_NUMBER CurrentIdealProcessor;  // 0x1744
    ULONG IdealProcessorValue;                       // 0x1744
    struct {
      UCHAR ReservedPad0;    // 0x1744
      UCHAR ReservedPad1;    // 0x1745
      UCHAR ReservedPad2;    // 0x1746
      UCHAR IdealProcessor;  // 0x1747
    };
  };
  ULONG GuaranteedStackBytes;          // 0x1748
  ULONGLONG ReservedForPerf;           // 0x1750
  ULONGLONG ReservedForOle;            // 0x1758
  ULONG WaitingOnLoaderLock;           // 0x1760
  ULONGLONG SavedPriorityState;        // 0x1768
  ULONGLONG SoftPatchPtr1;             // 0x1770
  ULONGLONG ThreadPoolData;            // 0x1778
  ULONGLONG TlsExpansionSlots;         // 0x1780
  ULONGLONG DeallocationBStore;        // 0x1788
  ULONGLONG BStoreLimit;               // 0x1790
  ULONG MuiGeneration;                 // 0x1798
  ULONG IsImpersonating;               // 0x179c
  ULONGLONG NlsCache;                  // 0x17a0
  ULONGLONG pShimData;                 // 0x17a8
  ULONG HeapVirtualAffinity;           // 0x17b0
  ULONGLONG CurrentTransactionHandle;  // 0x17b8
  ULONGLONG ActiveFrame;               // 0x17c0
  ULONGLONG FlsData;                   // 0x17c8
  ULONGLONG PreferredLanguages;        // 0x17d0
  ULONGLONG UserPrefLanguages;         // 0x17d8
  ULONGLONG MergedPrefLanguages;       // 0x17e0
  ULONG MuiImpersonation;              // 0x17e8
  union {
    volatile USHORT CrossTebFlags;  // 0x17ec
    USHORT SpareCrossTebBits : 16;  // 0x17ec
  };
  union {
    USHORT SameTebFlags;  // 0x17ee
    struct {
      USHORT SafeThunkCall : 1;         // 0x17ee
      USHORT InDebugPrint : 1;          // 0x17ee
      USHORT HasFiberData : 1;          // 0x17ee
      USHORT SkipThreadAttach : 1;      // 0x17ee
      USHORT WerInShipAssertCode : 1;   // 0x17ee
      USHORT RanProcessInit : 1;        // 0x17ee
      USHORT ClonedThread : 1;          // 0x17ee
      USHORT SuppressDebugMsg : 1;      // 0x17ee
      USHORT DisableUserStackWalk : 1;  // 0x17ee
      USHORT RtlExceptionAttached : 1;  // 0x17ee
      USHORT InitialThread : 1;         // 0x17ee
      USHORT SpareSameTebBits : 5;      // 0x17ee
    }SameTebFlagStruct;
  };
  ULONGLONG TxnScopeEnterCallback;  // 0x17f0
  ULONGLONG TxnScopeExitCallback;   // 0x17f8
  ULONGLONG TxnScopeContext;        // 0x1800
  ULONG LockCount;                  // 0x1808
  ULONG SpareUlong0;                // 0x180c
  ULONGLONG ResourceRetValue;       // 0x1810
}TEB64;
