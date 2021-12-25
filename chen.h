/**
 * @file chen.h
 * @author macrochen (macrochen@cqu.edu.cn)
 * @brief  This is a implementation of Chen et al. scheme. 
 * @version 0.1
 * @date 2021-12-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */


#ifndef _HEADER_CHEN_H_
#define _HEADER_CHEN_H_

#ifdef  __cplusplus
extern "C" {
#endif

#include <hiredis/hiredis.h>

void CKeyGen(char *ks, char *kk);

void CUpdate(redisContext* conn, char *ks, char *kk, char *keyword, int keywordlen, char *index);

void CTrapdoor(int &cu, char *kw, char *ig, char *ks, char *keyword, int keywordlen);

void CSearch(int &len, int cu, char *kw, char *ig);

void CDecrypt(int len, char *kk);
#ifdef  __cplusplus
}
#endif

#endif