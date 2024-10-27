#include "framework.h"
#include <windows.h>
#include <string>
#include <vector>
#define INRANGE(x,a,b)  (x >= a && x <= b) 
#define getBits( x )	(INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

PVOID
SundaySearch_ByProcess(
    HANDLE ProcesHandle,
    char* pattern,
    PVOID address,
    SIZE_T readSize
) {
    size_t patLen = strlen(pattern);

    patLen = (patLen + 1) / 3;
    if (readSize < patLen)
        return NULL;

    auto dataVec = std::vector<char>();
    dataVec.resize(readSize);
    SIZE_T bytesRead;
    SIZE_T TotalSize = readSize;
    SIZE_T CurOffset = 0;
    while (TotalSize)
    {
        ULONG64 ReadSize = min(0x1000, TotalSize);
        bytesRead = 0;
        auto ret = ReadProcessMemory(ProcesHandle, 
            (void*)((uint64_t)address + CurOffset),
            (PVOID)((uint64_t)dataVec.data() + CurOffset), ReadSize, &bytesRead);
        TotalSize -= bytesRead;
        CurOffset += bytesRead;
        if (ret != true) break;
        if (bytesRead == 0) break;
    }

    size_t i = 0;
    while (i < readSize)
    {
        size_t j = 0;

        UCHAR c1 = 0;
        UCHAR c2 = 0;

        while (j < patLen &&
            i + j < readSize &&
            (*(pattern + j * 3) == '\?' ||
                (c1 = dataVec[i + j]) == (c2 = getByte((pattern + j * 3)))))
        {
            j++;
        }

        if (j == patLen)
        {
            return (PVOID)((DWORD_PTR)address + i);
        }
        else
        {
            LONGLONG k = (LONGLONG)j;
            if (i + patLen < readSize)
            {
                for (k = (LONGLONG)(patLen - 1); k >= 0; k--)
                {
                    c1 = getByte((pattern + k * 3));
                    c2 = dataVec[i + patLen];

                    if (*(pattern + k * 3) == '\?' || c1 == c2)
                        break;
                }
            }
            i += (size_t)(patLen - k);
        }
    }

    return NULL;
}