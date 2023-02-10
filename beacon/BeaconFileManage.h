#pragma once
#include "Utils.h"
#include "comm.h"
#include "common.h"
#include <direct.h>

void BeaconLs(char* Taskdata, int Task_size);

void beacon_MkDir(char* Taskdata, int Task_size);

void GetDrivesList(char* Taskdata, int Task_size);

void beacon_rm(char* Taskdata, int Task_size);

typedef void(__cdecl *CallbackDelFilePtr)(const char* path, const char* name, int type);
void CallbackDelFile(const char* path, const char* name, int type);

void DeleteAllFile(char* buffer);

void TraverseDeleteFile(char* path, LPWIN32_FIND_DATAA lpFindFileData, CallbackDelFilePtr Callback_fun);

void RecursionTraverseDeleteFile(char* path, char* Name, LPWIN32_FIND_DATAA lpFindFileData, CallbackDelFilePtr Callback);

void beacon_copy(char* Taskdata, int Task_size);

void beacon_Move(char* Taskdata, int Task_size);