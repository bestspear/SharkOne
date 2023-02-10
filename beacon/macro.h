#pragma once
#ifdef _WIN64
#define CsC2Config_size 0x800
#define index_size 16
#else
#define CsC2Config_size 0x400
#define index_size 8
#endif // _WIN64