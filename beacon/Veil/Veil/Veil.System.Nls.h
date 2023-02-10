/*
 * PROJECT:   Veil
 * FILE:      Veil.h
 * PURPOSE:   Definition for the Windows Internal API from ntdll.dll,
 *            samlib.dll and winsta.dll
 *
 * LICENSE:   Relicensed under The MIT License from The CC BY 4.0 License
 *
 * DEVELOPER: MiroKaku (50670906+MiroKaku@users.noreply.github.com)
 */

 /*
  * PROJECT:   Mouri's Internal NT API Collections (MINT)
  * FILE:      MINT.h
  * PURPOSE:   Definition for the Windows Internal API from ntdll.dll,
  *            samlib.dll and winsta.dll
  *
  * LICENSE:   Relicensed under The MIT License from The CC BY 4.0 License
  *
  * DEVELOPER: Mouri_Naruto (Mouri_Naruto AT Outlook.com)
  */

  /*
   * This file is part of the Process Hacker project - https://processhacker.sf.io/
   *
   * You can redistribute this file and/or modify it under the terms of the
   * Attribution 4.0 International (CC BY 4.0) license.
   *
   * You must give appropriate credit, provide a link to the license, and
   * indicate if changes were made. You may do so in any reasonable manner, but
   * not in any way that suggests the licensor endorses you or your use.
   */

#pragma once

   // Warnings which disabled for compiling
#if _MSC_VER >= 1200
#pragma warning(push)
// nonstandard extension used : nameless struct/union
#pragma warning(disable:4201)
// 'struct_name' : structure was padded due to __declspec(align())
#pragma warning(disable:4324)
// 'enumeration': a forward declaration of an unscoped enumeration must have an
// underlying type (int assumed)
#pragma warning(disable:4471)
#endif

VEIL_BEGIN()

NTSYSAPI USHORT NlsAnsiCodePage;

#ifndef _KERNEL_MODE

#ifdef _NTSYSTEM_

// Try to avoid these, the preferred system ACP/OEMCP is UTF-8 and these are then irrelevent
#define NLS_MB_CODE_PAGE_TAG NlsMbCodePageTag
#define NLS_MB_OEM_CODE_PAGE_TAG NlsMbOemCodePageTag

#else

// Try to avoid these, the preferred system ACP/OEMCP is UTF-8 and these are then irrelevent
#define NLS_MB_CODE_PAGE_TAG (*NlsMbCodePageTag)
#define NLS_MB_OEM_CODE_PAGE_TAG (*NlsMbOemCodePageTag)

#endif // _NTSYSTEM_

extern BOOLEAN NLS_MB_CODE_PAGE_TAG;     // TRUE -> Multibyte CP, FALSE -> Singlebyte
extern BOOLEAN NLS_MB_OEM_CODE_PAGE_TAG; // TRUE -> Multibyte CP, FALSE -> Singlebyte

#define MAXIMUM_LEADBYTES 12

typedef struct _CPTABLEINFO
{
    USHORT CodePage;
    USHORT MaximumCharacterSize;
    USHORT DefaultChar;
    USHORT UniDefaultChar;
    USHORT TransDefaultChar;
    USHORT TransUniDefaultChar;
    USHORT DBCSCodePage;
    UCHAR LeadByte[MAXIMUM_LEADBYTES];
    PUSHORT MultiByteTable;
    PVOID WideCharTable;
    PUSHORT DBCSRanges;
    PUSHORT DBCSOffsets;
} CPTABLEINFO, * PCPTABLEINFO;

typedef struct _NLSTABLEINFO
{
    CPTABLEINFO OemTableInfo;
    CPTABLEINFO AnsiTableInfo;
    PUSHORT UpperCaseTable;
    PUSHORT LowerCaseTable;
} NLSTABLEINFO, * PNLSTABLEINFO;

#else // !_KERNEL_MODE

//
//  Code Page Default Values.
//  Please Use Unicode, either UTF-16 (as in WCHAR) or UTF-8 (code page CP_ACP)
//
#define CP_ACP                    0           // default to ANSI code page
#define CP_OEMCP                  1           // default to OEM  code page
#define CP_MACCP                  2           // default to MAC  code page
#define CP_THREAD_ACP             3           // current thread's ANSI code page
#define CP_SYMBOL                 42          // SYMBOL translations

#define CP_UTF7                   65000       // UTF-7 translation
#define CP_UTF8                   65001       // UTF-8 translation

#include <ntnls.h>

#endif // _KERNEL_MODE

VEIL_END()

#if _MSC_VER >= 1200
#pragma warning(pop)
#endif
