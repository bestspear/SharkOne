#pragma once
#include "Utils.h"
#include "common.h"
#include "comm.h"
#define JobNameMAX 64

#pragma pack(1)
struct BeaconJob
{
	int JobNumber;
	HANDLE pHandle;
	HANDLE hThread;
	int dwProcessId;
	int dwThreadId;
	HANDLE hReadPipe;
	HANDLE hWritePipe;
	BeaconJob* Linked;
	BOOL state;
	BOOL kill;
	int JobProcessPid;
	int JobType;
	short lasting;
	char JobName[JobNameMAX];
};
#pragma pack()

//任务数量
extern int g_job_Number;
extern BeaconJob* gBeaconJob;


void BeaconBackstageJob(int FlagsAndAttributes, char* Taskdata, int Task_size, int lasting);

void CheckTimeout(HANDLE hNamedPipe, int timeout);

void beacon_jobs();

void beacon_JobKill(char* Taskdata, int Task_size);

BOOL ConnectJobPipe(HANDLE* hNamedPipe, int dwFlagsAndAttributes, CHAR* NamedPipeName);

BeaconJob* Add_Beacon_0Job(HANDLE hProcess, HANDLE hThread, int dwProcessId, int dwThreadId, HANDLE hReadPipe, HANDLE hWritePipe, const char* jobname);

void CheckJobOutput();