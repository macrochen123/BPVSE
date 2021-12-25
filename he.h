/**
 * @file he.h
 * @author macrochen (macrochen@cqu.edu.cn)
 * @brief  This is a implementation of he et al. scheme. 
 * @version 0.1
 * @date 2021-12-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */


#ifndef _HEADER_HE_H_
#define _HEADER_HE_H_

#ifdef  __cplusplus
extern "C" {
#endif
#include <hiredis/hiredis.h>


void HKeyGen(char *ks);

void SubUpdata(char *st, char *index, int indexlen);

void HUpdate(redisContext* conn, char *ks, int &crt, char *W, int keywordlen, int wL, int fn,  char *sIndex);

void HTrapdoor(char* trapdoor, int crt, char *ks, char *keyword, int keywordlen);

void HSearch(int &len, char *trapdoor, int Clen, int crt);



#ifdef  __cplusplus
}
#endif

#endif