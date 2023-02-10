#pragma once
#include "Utils.h"
#pragma pack(1)
struct BeaconRportfwd
{
	int field_0;
	int state;
	int field_8_time;
	int field_C_time;
	int field_10;
	int port;
	int field_18;
	SOCKET socket;
	BeaconRportfwd* Linked;
};
#pragma pack()

extern BeaconRportfwd* gBeaconRportfwd;

int sub_10006D6B();

void sub_100071B7(char* Taskdata, int Task_size, int addr);

void sub_1000728D(char* Taskdata, int Task_size);

SOCKET BeaconNewSocket(int addr, u_short port, int backlog);

void Add_Beacon_Rportfwd(int unknown, SOCKET socket, int a3, int a4, int port, int a6);

void sub_10006D81();

int sub_1000707E();

void sub_10006FF5();

void sub_10006B2B(char* Taskdata, int taskdatasize);

void sub_10006CFC(char* Taskdata, int taskdatasize);

void sub_10006ACD(char* Taskdata);