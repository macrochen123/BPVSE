/**
 * @file song.h
 * @author macrochen (macrochen@cqu.edu.cn)
 * @brief  This is a implementation of Song et al. scheme. 
 * @version 0.1
 * @date 2021-12-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */


#ifndef _HEADER_SONG_H_
#define _HEADER_SONG_H_

#ifdef  __cplusplus
extern "C" {
#endif
#include <hiredis/hiredis.h>


void SKeyGen(char *ks);

void SUpdate(redisContext* conn, char *ks, char *keyword, int keywordlen, char *index, int indexlen);

void STrapdoor(char* trapdoor, int &count, char *ks, char *keyword, int keywordlen);

void SSearch(int &len, char *trapdoor, int count);



#ifdef  __cplusplus
}
#endif

#endif