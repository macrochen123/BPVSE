#ifndef _HEADER_UTIL_H_
#define _HEADER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#include "miracl.h"
}
#else
#include "miracl.h"
#endif

#include <map>
#include <string>
using std::string;

#define KEY_LEN 32
#define HASH_LEN 32
#define WORD_LEN 8
//for the encode/decode
#define OFFSET 65

#define HASH_SIZE	32

#define CLEN 32

#ifdef  __cplusplus
extern "C" {
#endif

void gh(char *hash, char *message, int mlen);
void h(char *hash,  char *message, int mlen, int flag);
void h2(char *hash, char *message, int mlen);
void h34(char *hash, char *message, int mlen, int index, int flag);
void F1(char *hash, char *keyword, int keywordlen, char *version, char *key, int flag);
void hkey(char *hash,  char *hd, char *pv, int len, char *st, int stlen);
void addHash(char *newhash, char *oldhash, char *message, int mlen);
void LMHash(char *hash, char *message, int mlen);
void Reset(char *source, int mlen);

void strPrint(char *source, int slen);
void randomStr(char *output, int len);
void strCopy(char *output, char *source, int len);
bool strequal(char *sourceA, char *sourceB, int len);
void strXor(char * output, char *sourceA, char *sourceB, int len);
void int2char(char *output, int input);
int char2int(char *source, int mlen);
string char2str(char *source, int clen);
int str2char(char *output, string str);

void PointPrint(epoint *PK);
void StrPrint(string str);

///**the multi set hash///
void Hash(char *hash, char *IV, char *M, int mLen);
void MulHash(char *hash, char *IV, char *asource, char *bsource);
void HomHash(char *hash, char *IV, char *hasha, char *hashb);

void ZF1(char* hash, char *ks, char *keyword, int keywordlen);
void ZF2(char *hash, char *kr, char *keyword, int keywordlen);

void ZH1(char *hash , char *tw, char *st1, int len);//2HASHLEN
void ZH2(char *hash , char *tw, char *st1, int len);//2HASHLEN


///Encode
void Encode(char *output, char *input, int len);
void Decode(char *output, char *input, int len);
string Setcomm(char *inputK, int klen, char *inputV, int vlen);
string Getcomm(char *inputK, int klen);

string SetcommInt(int inputK, char *inputV, int vlen);
string GetcommInt(int inputK);

//
void SF(char *hash, char *key, int klen, char *hw, int hlen);
void SH1(char *hash, char *tw, char *st, int len);
void SH2(char *hash, char *tw, char *st, int len);//2*HASH_LEN

//
void HH(char *hash, char *st, int len);
void HF(char *hash, char *k, int klen, char *keyword, int keywordlen);
void HHF(char *hash, char *kt, int len, int crt);
void HHI(char *newhash, char *oldhash);

//
//K_w = F(s,w,c)
void CF(char *hash, char *ks, char *keyword, int keywordlen, int flag);
void CH(char *hash, char *kw, int cu);//2*HASH_LEN
void CGI(char *hash, char *kw1, char *index, int indexlen);
#ifdef  __cplusplus
}
#endif

#endif // !_HEADER_Curve_CURVE_H_
