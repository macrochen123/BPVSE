/**
 * @file Zhang.h
 * @author macrochen (macrochen@cqu.edu.cn)
 * @brief  This is a implementation of Zhang et al. scheme. 
 * @version 0.1
 * @date 2021-11-09
 * 
 * @copyright Copyright (c) 2021
 * 
 */


#ifndef _HEADER_ZHANG_H_
#define _HEADER_ZHANG_H_

#ifdef  __cplusplus
extern "C" {
#endif
#include <hiredis/hiredis.h>

/**
 * @brief The key generation algorithm
 * 
 * @param ks a secret key
 * @param kr a secret key
 */
void ZKeyGen(char *ks, char *kr);

/**
 * @brief The encryption algorithm 
 * 
 * @param conn a handle of Redis dataset
 * @param ks 
 * @param kr 
 * @param keyword a keyword 
 * @param keywordlen the length of keyword
 * @param index the index set of files containing the corresponding keyword
 * @param indexlen the size of index set
 */
void ZUpdate(redisContext* conn, char *ks, char *kr, char *keyword, int keywordlen, char *index, int indexlen);

/**
 * @brief The trapdoor generation algorithm, which is run by the data owner
 * 
 * @param trapdoor a trapdoor to search the matching indexes
 * @param ks a secret key
 * @param keyword the keyword to be search
 * @param keywordlen the length of the keyword
 */
void ZTrapdoor(char *trapdoor, char *ks, char *keyword, int keywordlen);
/**
 * @brief This is a search algorithm, which is run by the search server. The algorithm includes the dataset operations
 * 
 * @param len this is an output, the search result
 * @param proof this is an output, a proof about the search result
 * @param trapdoor this is an input, a trapdoor containing a keyword
 */
void ZSearch(int &len,  char *proof, char *trapdoor);
/**
 * @brief This also is a search algorithm, but it searches the result in memory
 * 
 * @param len 
 * @param proof 
 * @param trapdoor 
 */
void ZSearchE(int &len, char *proof,  char *trapdoor);
/**
 * @brief This is a verify algorithm, which is to determine whether the search result is correct. The algorithm includes the dataset operations
 * 
 * @param result 
 * @param len 
 * @param proof 
 * @param ks 
 * @param kr 
 * @param keyword 
 * @param keywordlen 
 */
void ZVerify(char *result, int len, char *proof, char *ks, char *kr, char *keyword, int keywordlen);
/**
 * @brief This also is a verify algorithm, but the verify process is run in memory 
 * 
 * @param len 
 * @param proof 
 * @param ks 
 * @param kr 
 * @param keyword 
 * @param keywordlen 
 */
void ZVerifyE(int len, char *proof, char *ks, char *kr, char *keyword, int keywordlen);




#ifdef  __cplusplus
}
#endif

#endif