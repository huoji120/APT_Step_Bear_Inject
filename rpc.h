#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <Rpc.h>
#include <rpcndr.h>

typedef struct _NDR64_PROC_FORMAT
{
    /* 0x0000 */ unsigned int Flags;
    /* 0x0004 */ unsigned int StackSize;
    /* 0x0008 */ unsigned int ConstantClientBufferSize;
    /* 0x000c */ unsigned int ConstantServerBufferSize;
    /* 0x0010 */ unsigned short RpcFlags;
    /* 0x0012 */ unsigned short FloatDoubleMask;
    /* 0x0014 */ unsigned short NumberOfParams;
    /* 0x0016 */ unsigned short ExtensionSize;
} NDR64_PROC_FORMAT, *PNDR64_PROC_FORMAT; /* size: 0x0018 */

/*
#define ULONG_PTR_T ULONG_PTR
#define PTR_T *

typedef struct _RPC_DISPATCH_TABLE_T {
    UINT							DispatchTableCount;
    RPC_DISPATCH_FUNCTION  PTR_T	DispatchTable;
    ULONG_PTR_T                      Reserved;
} RPC_DISPATCH_TABLE_T, PTR_T PRPC_DISPATCH_TABLE_T;

typedef struct _RPC_PROTSEQ_ENDPOINT_T {
    UCHAR PTR_T RpcProtocolSequence;
    UCHAR PTR_T Endpoint;
} RPC_PROTSEQ_ENDPOINT_T, PTR_T PRPC_PROTSEQ_ENDPOINT_T;

typedef struct _RPC_SERVER_INTERFACE_T {
    UINT					Length;
    RPC_IF_ID				InterfaceId;
    RPC_IF_ID				TransferSyntax;
    PRPC_DISPATCH_TABLE_T	DispatchTable;
    UINT					RpcProtseqEndpointCount;
    PRPC_PROTSEQ_ENDPOINT_T RpcProtseqEndpoint;
    RPC_MGR_EPV PTR_T		DefaultManagerEpv;
    void const PTR_T		InterpreterInfo;
    UINT					Flags;
} RPC_SERVER_INTERFACE_T, PTR_T PRPC_SERVER_INTERFACE_T;


typedef struct _NDR_EXPR_DESC_T
{
    const unsigned short PTR_T	pOffset;
    const unsigned char	PTR_T	pFormatExpr;
} NDR_EXPR_DESC_T;


typedef struct _MIDL_STUB_DESC_T {
    void  PTR_T						RpcInterfaceInformation;
    void  PTR_T						pfnAllocate;
    void  PTR_T						pfnFree;
    void  PTR_T						pAutoHandle;
    const VOID  PTR_T				apfnNdrRundownRoutines;
    const VOID  PTR_T				aGenericBindingRoutinePairs;
    const VOID  PTR_T				apfnExprEval;
    const VOID  PTR_T				aXmitQuintuple;
    const unsigned char  PTR_T		pFormatTypes;
    int								fCheckBounds;
    unsigned long					Version;
    VOID PTR_T						pMallocFreeStruct;
    long							MIDLVersion;
    const COMM_FAULT_OFFSETS  PTR_T	CommFaultOffsets;
    // New fields for version 3.0+
    const VOID PTR_T				aUserMarshalQuadruple;
    // Notify routines - added for NT5, MIDL 5.0
    const VOID PTR_T				NotifyRoutineTable;

    ULONG_PTR_T						mFlags;
    // International support routines - added for 64bit post NT5
    const VOID	PTR_T				CsRoutineTables;
    void  PTR_T						ProxyServerInfo;
    const NDR_EXPR_DESC_T	PTR_T	pExprInfo;
    // Fields up to now present in win2000 release.
} MIDL_STUB_DESC_T, PTR_T PMIDL_STUB_DESC_T;

typedef struct  _MIDL_SERVER_INFO_T {
    PMIDL_STUB_DESC_T				pStubDesc;
    const VOID	PTR_T	PTR_T		DispatchTable;
    const unsigned char		PTR_T	ProcString;
    const unsigned short	PTR_T	FmtStringOffset;
    const VOID PTR_T PTR_T			ThunkTable;
    RPC_IF_ID PTR_T					pTransferSyntax;
    ULONG_PTR_T						nCount;
    VOID PTR_T						pSyntaxInfo;
} MIDL_SERVER_INFO_T, PTR_T PMIDL_SERVER_INFO_T;
*/