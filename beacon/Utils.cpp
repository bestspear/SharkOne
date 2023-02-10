#include "Utils.h"
#include "Global.h"
#include "macro.h"

void BeaconDataParse(datap* parser, char* buffer, int size)
{
	parser->original = buffer;
	parser->buffer = buffer;
	parser->length = size;
	parser->size = size;
}
void BeaconDataFree(datap* parser)
{
	free(parser->original);
	free(parser);
}

void BeaconDataClear(datap* parser)
{
	memset(parser->original, 0, parser->size);
}
char* BeaconDataPtr(datap* parser, int size)
{
	char* result = 0;
	if (parser->length < size)
	{
		return 0;
	}
	result = parser->buffer;
	parser->buffer += size;
	parser->length -= size;
	return result;
}

int	BeaconDataInt(datap* parser)
{
	int result;
	if (parser->length < sizeof(int))
	{
		return 0;
	}
	result = ntohl(*(u_long*)parser->buffer);
	parser->buffer += sizeof(int);
	parser->length += sizeof(int);
	return result;
}

short BeaconDataShort(datap* parser)
{
	short result;

	if (parser->length < sizeof(short))
	{
		return 0;
	}
	result = ntohs(*(u_short*)parser->buffer);
	parser->buffer += sizeof(short);
	parser->length -= sizeof(short);
	return result;
}

int	BeaconDataLength(datap* parser)
{
	return parser->length;
}


int BeaconDataCopyToBuffer(datap* parser, char* buffer,int buffer_size)
{
	int copy_size = BeaconDataInt(parser);
	if (!copy_size)
	{
		return 0;
	}
	if (copy_size + 1 > buffer_size)
	{
		return 0;
	}
	char* data = BeaconDataPtr(parser, copy_size);
	if (!data)
	{
		return 0;
	}
	memcpy(buffer, data, copy_size);
	buffer[copy_size] = 0;
	return copy_size + 1;
}

void BeaconDataCopyNToBuffer(datap* parser, char* buffer, int buffer_size)
{
	int length = parser->length;
	if (length + 1 < buffer_size)
	{
		memcpy(buffer, parser->buffer, parser->length);
		buffer[length] = 0;
	}
}



char* BeaconDataPtr2(datap* parser)
{
	int size = BeaconDataInt(parser);
	if (size)
	{
		return BeaconDataPtr(parser, size);
	}
	return 0;
}

char* BeaconDataPtr3(datap* parser, int* outsize)
{
	int size = BeaconDataInt(parser);
	if (size)
	{
		*outsize = size;
		return BeaconDataPtr(parser, size);
		
	}
	return 0;
}
char* BeaconDataExtract(datap* parser, int* outsize)
{
	int size = 0;
	char* data = BeaconDataPtr3(parser, &size);
	if (outsize)
	{
		*outsize = size;
	}
	return size != 0 ? data : 0;
}

datap* BeaconDataInit(int size)
{
	char* pdata;
	datap* pdatap;

	pdatap = (datap*)malloc(sizeof(datap));
	if (!pdatap)
	{
		return 0;
	}
	pdata = (char*)malloc(size);
	if (!pdata)
	{
		return 0;
	}
	memset(pdata, 0, size);
	BeaconDataParse(pdatap, pdata, size);
	return pdatap;
}

char BeaconDataByte(datap* parser) 
{
	if (!parser->length)
	{
		return 0;
	}
	char* ret = parser->buffer;
	parser->buffer += 1;
	parser->length -= 1;
	return *ret;
}

char* BeaconDataBuffer(datap* parser)
{
	return parser->buffer;
}

void BeaconDataClearFree(datap* parser)
{
	BeaconDataClear(parser);
	BeaconDataFree(parser);
}

void BeaconFormatInit(formatp* format, char* buff, int buffsize)
{
	format->length = 0;
	format->original = buff;
	format->buffer = buff;
	format->size = buffsize;
	memset(buff, 0, buffsize);
}

void BeaconFormatAlloc(formatp* format, int maxsz)
{
	char* buff = (char*)malloc(maxsz);
	return BeaconFormatInit(format, buff, maxsz);
}

void BeaconFormatReset(formatp* format)
{
	format->buffer = format->original;
	format->length = 0;
}

void BeaconFormatFree(formatp* format)
{
	memset(format->original, 0, format->size);
	free(format->original);
}

void BeaconFormatAppend(formatp* format, char* text, int len)
{
	if (len < format->size - format->length)
	{
		if (len)
		{
			memcpy(format->buffer, text, len);
			format->buffer += len;
			format->length += len;
		}
	}
}
void BeaconFormatPrintf(formatp* format, char* fmt, ...)
{
	va_list ArgList;
	va_start(ArgList, fmt);
	int v2 = vprintf(fmt, ArgList);
	if (v2 > 0)
	{
		int size = format->size - format->length;
		if (v2 < size)
		{
			int v4 = vsprintf_s(format->buffer, size, fmt, ArgList);
			format->buffer += v4;
			format->length += v4;
		}
	}
}
char* BeaconFormatToString(formatp* format, int* size)
{
	if (!size)
	{
		return 0;
	}
	int length = BeaconFormatlength(format);
	*size = length;
	return BeaconFormatOriginalPtr(format);
}
void BeaconFormatInt(formatp* format, int value)
{
	value = htonl(value);
	BeaconFormatAppend(format, (char*)&value, 4);
}

int BeaconFormatlength(formatp* format)
{
	return format->length;
}
char* BeaconFormatOriginalPtr(formatp* format)
{
	return format->original;
}


void GetParseConfig(beaconconfig* pbeaconconfig, int id)
{
	pbeaconconfig->data = CsC2Config + index_size * id + sizeof(size_t);
	pbeaconconfig->data_type = *(short*)(CsC2Config + index_size * id);

}


char* get_str(int id)
{
	beaconconfig pbeaconconfig;
	GetParseConfig(&pbeaconconfig, id);
	if (pbeaconconfig.data_type == 3)
	{
		return (char*)*(ULONG_PTR*)pbeaconconfig.data;
	}
	return 0;
}
short get_short(int id)
{
	beaconconfig pbeaconconfig;
	GetParseConfig(&pbeaconconfig, id);
	if (pbeaconconfig.data_type == 1)
	{
		return *(WORD*)pbeaconconfig.data;
	}
	return 0;
}
int get_dword(int id)
{
	beaconconfig pbeaconconfig;
	GetParseConfig(&pbeaconconfig, id);
	if (pbeaconconfig.data_type == 2)
	{
		return *(DWORD*)pbeaconconfig.data;
	}
	return 0;
}

int get_str_config_len(int id)
{
	return strlen(get_str(id));
}

/// <summary>
/// 初始化元数据结构体
/// </summary>
/// <param name="pmetadata"></param>
/// <param name="data"></param>
/// <param name="data_size"></param>
void BeaconMetadataInit(beaconmetadata* pmetadata, char* data, int data_size)
{
	DWORD number = htonl(MetadataNumber);
	u_long reserve = htonl(0);

	++MetadataNumber;
	DWORD* pdata = (DWORD*)data;
	pdata[0] = number;
	pdata[1] = reserve;

	pmetadata->data = data;
	pmetadata->data_size = data_size;

	pmetadata->length = 8;
}

/// <summary>
/// 保存N字节到元数据中
/// </summary>
/// <param name="size"></param>
/// <param name="struc3"></param>
/// <param name="data"></param>
void BeaconMetadataPush_N(size_t size, beaconmetadata* pmetadata, void* data)
{

	DWORD new_length = pmetadata->length + size;
	if ((signed int)(pmetadata->length + size) <= pmetadata->data_size)
	{
		memcpy(pmetadata->data + pmetadata->length, data, size);
		pmetadata->length = new_length;
		((DWORD*)pmetadata->data)[1] = ntohl(new_length - 8);
	}
}

void BeaconMetadataPush_4(int data, beaconmetadata* pmetadata)
{
	data = htonl(data);
	BeaconMetadataPush_N(4, pmetadata, &data);
}
void BeaconMetadataPush_2(short data, beaconmetadata* pmetadata)
{
	data = htons(data);
	BeaconMetadataPush_N(2, pmetadata, &data);
}
void BeaconMetadataPush_1(char data, beaconmetadata* pmetadata)
{
	BeaconMetadataPush_N(1, pmetadata, &data);
}

DWORD BeaconMetadataLength(beaconmetadata* pmetadata)
{
	*(DWORD*)pmetadata->data = htonl(48879);
	return pmetadata->length;
}
DWORD BeaconMetadataDataLength(beaconmetadata* pmetadata)
{
	return pmetadata->length;
}