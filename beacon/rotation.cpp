#include "rotation.h"
#include <time.h>
/// <summary>
/// 初始化轮询结构体
/// </summary>
/// <param name="rotation_opt"></param>
/// <param name="strategyID"></param>
/// <param name="rotate_Strategy_time"></param>
/// <param name="failover_Strategy_time"></param>
/// <param name="failover_Strategy_number"></param>
void init_rotation(rotationstruc* rotation_opt, int strategyID, int rotate_Strategy_time, int failover_Strategy_time, int failover_Strategy_number)
{
	rotation_opt->strategyID = strategyID;
	rotation_opt->rotate_Strategy_time = rotate_Strategy_time;
	rotation_opt->failover_Strategy_time = failover_Strategy_time;
	rotation_opt->failover_Strategy_number = failover_Strategy_number;
}

/// <summary>
/// 随机模式下ip存储缓冲区
/// </summary>
char* ServerIP_Buff_random=NULL;

/// <summary>
/// 随机模式下ip数量
/// </summary>
int g_ip_number_random=0;

/// <summary>
/// 随机模式下当前ip索引
/// </summary>
int g_current_ip_index_random=0;

/// <summary>
/// 随机模式下ip指针数组
/// </summary>
char* g_ip_array_random[200];

int random_int(int seed)
{
    return rand() % (seed + 1);
}
int random_ipid(int ip_id)
{
    return ip_id - ip_id % 2;
}

/// <summary>
/// 随机选择ip
/// </summary>
/// <param name="ServerIP"></param>
/// <returns></returns>
char* random_selection(char* ServerIP)
{
    int current_ip_id = 0;
    int ip_id = 0 ;

    if (ServerIP_Buff_random)
    {
        current_ip_id = g_current_ip_index_random;
    }
    else
    {
        ServerIP_Buff_random = (char*)malloc(strlen(ServerIP) + 1);
        strncpy(ServerIP_Buff_random, ServerIP, strlen(ServerIP) + 1);
        g_ip_number_random = 0;
        for (char* ip = strtok(ServerIP_Buff_random, ","); ip; ip = strtok(0, ","))
        {
            int ip_id = g_ip_number_random++;
            g_ip_array_random[ip_id] = ip;
        }
        current_ip_id = -1;
        g_current_ip_index_random = -1;
    }
    if (current_ip_id < 0 || current_ip_id >= g_ip_number_random)
    {
        ip_id = random_int(g_ip_number_random - 1);
        ip_id = random_ipid(ip_id);
        g_current_ip_index_random = ip_id;
    }
    else
    {
        ip_id = current_ip_id + 1;
        g_current_ip_index_random =- 1;
    }
    return g_ip_array_random[ip_id];
}

/// <summary>
/// 轮询模式下ip缓冲区
/// </summary>
char* ServerIP_Buff_carousel;

/// <summary>
/// 轮询 错误切换根据错误次数切换的指定错误次数
/// </summary>
int g_failover_Strategy_number;

/// <summary>
/// 轮询 错误切换根据时间切换的间隔时间
/// </summary>
int g_failover_Strategy_time;
/// <summary>
/// 轮询模式的ip数量
/// </summary>
int g_ip_number_carousel;

/// <summary>
/// 轮询模式的ip数组,保存所有的ip指针
/// </summary>
char* g_ip_array_carousel[200];

/// <summary>
/// 轮询模式下当前使用的ip索引,通过此id从数组里取ip指针
/// </summary>
int g_ip_index_carousel;

/// <summary>
/// 
/// </summary>
__int64 g_time;

/// <summary>
/// 轮询 定时切换 间隔时间
/// </summary>
int g_rotate_Strategy_time;

/// <summary>
/// 根据错误时间进行轮询
/// </summary>
__int64 g_failover_time;

/// <summary>
/// 错误次数
/// </summary>
int g_failover_number;

int dword_10037E80;
char* carousel(rotationstruc* rotation_opt, char* ServerIP, int number)
{
    char* ipsrc;
    int ip_id;
    signed int failover_Strategy_number;
    signed int failover_Strategy_time;
    char* result;
    __time64_t current_time;
    int v10;

    v10 = 0;
    current_time = _time64(0);
    if (ServerIP_Buff_carousel)
    {
        failover_Strategy_number = g_failover_Strategy_number;
        failover_Strategy_time = g_failover_Strategy_time;
    }
    else
    {
        ServerIP_Buff_carousel = (char*)malloc(strlen(ServerIP) + 1);
        strncpy(ServerIP_Buff_carousel, ServerIP, strlen(ServerIP) + 1);
        g_ip_number_carousel = 0;
        for (ipsrc = strtok(ServerIP_Buff_carousel, ","); ipsrc; ipsrc = strtok(0, ","))
        {
            ip_id = g_ip_number_carousel++;
            g_ip_array_carousel[ip_id] = ipsrc;
        }
        g_ip_index_carousel = 0;
        g_time = _time64(0);
        failover_Strategy_number = rotation_opt->failover_Strategy_number;
        g_rotate_Strategy_time = rotation_opt->rotate_Strategy_time;
        failover_Strategy_time = rotation_opt->failover_Strategy_time;
        g_failover_time = 0i64;
        g_failover_Strategy_number = failover_Strategy_number;
        g_failover_Strategy_time = failover_Strategy_time;
    }
    if (number)
    {
        if (failover_Strategy_number > -1 && ++g_failover_number > failover_Strategy_number)
        {
            v10 = 1;
        }
        if (failover_Strategy_time > -1)
        {
            if (g_failover_time)
            {
                if (current_time > g_failover_time + failover_Strategy_time)
                {
                    v10 = 1;
                }
            }
            else
            {
                g_failover_time = _time64(0);
            }
        }
    }
    else if (!dword_10037E80)
    {
        g_failover_time = 0i64;
        g_failover_number = 0;
    }
    if (g_rotate_Strategy_time <= -1)
    {
        goto LABEL_23;
    }
    if (!v10)
    {
        if (dword_10037E80)
        {
            result = g_ip_array_carousel[g_ip_index_carousel + 1];
            dword_10037E80 = 0;
            return result;
        }
        if (current_time <= g_time + g_rotate_Strategy_time)
        {
            result = g_ip_array_carousel[g_ip_index_carousel];
            dword_10037E80 = 1;
            return result;
        }
        v10 = 1;
    LABEL_23:
        if (!v10)
        {
            if (!dword_10037E80)
            {
                result = g_ip_array_carousel[g_ip_index_carousel];
                dword_10037E80 = 1;
                return result;
            }
            result = g_ip_array_carousel[g_ip_index_carousel + 1];
            dword_10037E80 = 0;
            return result;
        }
    }
    g_ip_index_carousel += 2;
    g_failover_number = 0;
    dword_10037E80 = 0;
    g_failover_time = 0i64;
    if (g_ip_index_carousel >= g_ip_number_carousel)
    {
        g_ip_index_carousel = 0;
    }
    g_time = _time64(0);
    if (!dword_10037E80)
    {
        result = g_ip_array_carousel[g_ip_index_carousel];
        dword_10037E80 = 1;
        return result;
    }
    result = g_ip_array_carousel[g_ip_index_carousel + 1];
    dword_10037E80 = 0;
    return result;
}

char* g_ServerIP_Buff;
char* no_rotation(char* ServerIP)
{
    char* result;

    if (g_ServerIP_Buff)
    {
        result = strtok(0, ",");
        if (result)
        {
            return result;
        }
        free(g_ServerIP_Buff);
    }
    g_ServerIP_Buff = (char*)malloc(strlen(ServerIP) + 1);
    strncpy(g_ServerIP_Buff, ServerIP, strlen(ServerIP) + 1);
    return strtok(g_ServerIP_Buff, ",");
}

/// <summary>
/// 轮询模式 错误切换 定时切换
/// </summary>
/// <param name="rotation_opt"></param>
/// <param name="ServerIP"></param>
/// <param name="number"></param>
/// <returns></returns>
char* beacon_Rotation_Strategy(rotationstruc* rotation_opt, char* ServerIP, int number)
{
	if (rotation_opt->strategyID == 1)// random 随机选择
	{
		return (char*)random_selection(ServerIP);
	}
	if (rotation_opt->strategyID == 2)//rotate或failover 
	{
		return (char*)carousel(rotation_opt, ServerIP, number);
	}
	return no_rotation(ServerIP); // 非轮询
}