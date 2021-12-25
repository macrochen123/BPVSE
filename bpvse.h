#ifndef _HEADER_SM2_H_
#define _HEADER_SM2_H_

#ifdef __cplusplus
extern "C" {
#include "miracl.h"
}
#else
#include "miracl.h"
#endif

#include <map>
#include <string>


#ifdef CURVE80
#define CURVE_SIZE 20
#else
#define CURVE_SIZE 32
#endif

#define MAX_INDEX_LEN 32
#define HASH_LEN  32
#define ERR_ECURVE_INIT           0xFFFFFF01
#define KEYWORDLEN 2


#define NUM_THREADS 5

#ifdef  __cplusplus
extern "C" {
#endif



/***
 * 
 * the setup of the system: including the elle
*/
int Curve_Init();
/**
 * intput: 
 *     k: the private key
 * output:
 *     kP: the public key
*/
void KeyGen(epoint *kP, big k);
/**
 * the trapdoor to generate a trapdoor for searching all matching indexes
 * input: 
 *       uPK: the public key of data user
 *       osk: the private key of data owner
 *       l: the curre version for encrypting the idnexes
 *       W: all keyword set //w_1, w_2,...
 *       DB[i]: each size of indexes set
 *       wL: the number of keywords
 *       sIndex: all index 
 *    
 * output:
 *       stl: the current state for this update 
 * 
 * **/
int UPdate(char *stl, char *ckey, int l, char *W, int *DB, int wL, char *sIndex);
/**
 * the trapdoor to generate a trapdoor for searching all matching indexes
 * input: 
 *       oPK: the public key of data owner
 *       usk: the private key of data user
 *       l: the version of state
 *       keyword: the keyword to be search
 *       wordLen: the length of the keyword
 * output:
 *       trapdoor
 * 
 * **/
void Trapdoor(char *trapdoor, char *ckey, int l, char *keyword, int wordLen);
/**
 * the search algorithm to find all matching indexes(a single-threaded environment).
 * input: trapdoor
 * output:
 *       result: R_{l}, R_{l-1}, ....., R_{1}
 *       resultLen: the total byte length of R
 *       aRlen: the array of sizes of R_{i}
 *       ast: the st array of st_{l}, st_{l-1}...
 *       astlen: the size of ast 
 * 
 * **/
int Search(int &resultLen, int &astLen,  char *Trapdoor);
/**
 * the verify algorithm to determine 
 * input: 
 *     aRlen: each size of R
 *     ast: the state array 
 *     astLen: the size of ast
 * output:
 *     result: the search result
 *     resultLen: the length of the search result
 * **/
bool Verify(int resultLen, int astLen);
/**
 * the search algorithm to find all matching indexes.
 * input: 
 *       oPK: the public key of the data owner
 *       usk: the private key of the data user
 *       result: the search result.
 *       resultLen: the length of returned result
 *       aVer: the version array
 *       averLen: the length of aVer
 *       keyword: the keyword corresponding to the 
 *       wordlen: the length of keyword
 * output:
 *       Message: the retrieve message
 *       outputlen: the length of indexes
 * 
 * **/
void Decryption(char *Message, int & outputlen, char *ckey, char *result, int resultLen, int *aRlen, char *aVer, int averLen, char *keyword, int wordLen);

/**
 * get the Diffie-Hellman key
 * input: 
 *      PK: a public key
 *      sk: a private key
 * output:
 *      ckey: the key (char* type)
 * 
 * 
*/
void GetKey(char *ckey, epoint *PK, big sk);


int TUPdate(char *stl, char *ckey, int l, char *W, int *DB, int wL, char *sIndex);
/**
 * @brief this is a multi-threads search algorithm 
 * 
 * @param resultLen: the matching results 
 * @param astLen: the size of each R
 * @param Trapdoor: the search trapdoor
 * @return * void 
 */
void MultiSearch(int &resultLen, int &astLen,  char *Trapdoor);
/**
 * @brief The core of search algorithm
 * 
 * @param data the input parameter, including the previous state, the current state, the total number of matching indexes, the ID of thread, and so on.
 * @return void* 
 */
void *SearchCore(void *data);


#ifdef  __cplusplus
}
#endif

#endif