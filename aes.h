#ifndef __HEADER_AES_H__
#define __HEADER_AES_H__

#include "mirdef.h"

#ifdef MR_CPP
#include "miracl.h"
#else
extern "C"                    
{
    #include "miracl.h"
}
#endif

#define S8 char
#define  U8 unsigned char
#define  U32 unsigned int

#define  S32 int

#define MAX_BLOCK_SIZE 16

#ifdef __cplusplus //|| defined(c_plusplus)
extern "C"{
#endif

	///自定义函数
	S32 AES_Get_C_Len(S32 M_Len,S32 Block_S);
	S32 AES_E(U8* Cipher,U8 *Message,U8* Key,S32 M_Len);
	S32 AES_D(U8* Message,U8* Cipher,U8* Key,S32 C_Len);

#ifdef __cplusplus 
}
#endif

#endif