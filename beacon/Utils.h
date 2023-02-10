#pragma once
#include "Global.h"

typedef struct {
	char* original; /* 原始缓冲区 [所以我们可以释放它] */
	char* buffer;   /* 指向当前缓冲区位置 */
	int    length;   /* 剩余数据长度 */
	int    size;     /* 此缓冲区的总大小 */
} datap;

void BeaconDataParse(datap* parser, char* buffer, int size);
char* BeaconDataPtr(datap* parser, int size);
int	BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int	BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);
datap* BeaconDataInit(int size);
void BeaconDataFree(datap* parser);
void BeaconDataClear(datap* parser);
int BeaconDataCopyToBuffer(datap* parser, char* buffer, int buffer_size);
char BeaconDataByte(datap* parser);
char* BeaconDataPtr2(datap* parser);
char* BeaconDataBuffer(datap* parser);
void BeaconDataCopyNToBuffer(datap* parser, char* buffer, int buffer_size);
char* BeaconDataPtr3(datap* parser, int* outsize);
char* BeaconDataExtract(datap* parser, int* outsize);

/* format API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

void BeaconFormatAlloc(formatp* format, int maxsz);
void BeaconFormatReset(formatp* format);
void BeaconFormatFree(formatp* format);
void BeaconFormatAppend(formatp* format, char* text, int len);
void BeaconFormatPrintf(formatp* format, char* fmt, ...);
char* BeaconFormatToString(formatp* format, int* size);
void BeaconFormatInt(formatp* format, int value);
int BeaconFormatlength(formatp* format);
char* BeaconFormatOriginalPtr(formatp* format);
void BeaconFormatInit(formatp* format, char* buff, int buffsize);
void BeaconDataClearFree(datap* parser);
typedef struct {
	char* data; /*指向data*/
	short data_type;   /* 指向data类型 */
} beaconconfig;
void GetParseConfig(beaconconfig* pbeaconconfig, int id);
char* get_str(int id);
short get_short(int id);
int get_dword(int id);
int get_str_config_len(int id);

/// <summary>
/// 元数据相关
/// </summary>
typedef struct {
	char* data; /*指向data*/
	int length;   /* data以使用字节 */
	int data_size; /*data内存块的大小*/
} beaconmetadata;




void BeaconMetadataInit(beaconmetadata* pmetadata, char* data, int data_size);

void BeaconMetadataPush_N(size_t size, beaconmetadata* pmetadata, void* data);
void BeaconMetadataPush_4(int data, beaconmetadata* pmetadata);
void BeaconMetadataPush_2(short data, beaconmetadata* pmetadata);
void BeaconMetadataPush_1(char data, beaconmetadata* pmetadata);
DWORD BeaconMetadataLength(beaconmetadata* pmetadata);
DWORD BeaconMetadataDataLength(beaconmetadata* pmetadata);