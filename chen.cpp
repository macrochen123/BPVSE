#include "chen.h"
#include "util.h"
#include <string>
#include "aes.h"

struct Sus{
    int cu;
    int cs;
};

std::map< string,  Sus> CC;
std::map< string,  string> CD;
std::map< string,  string> CG;

std::map< int,  string> Cr;


void CKeyGen(char *ks, char *kk)
{
    randomStr(ks, HASH_LEN);
    randomStr(kk, HASH_LEN);
}

void CUpdate(redisContext* conn, char *ks, char *kk, char *keyword, int keywordlen, char *index)
{
    int cu;
    int cs;
    char kw[HASH_LEN];
    char kw1[HASH_LEN];
    char hk[2*HASH_LEN];
    char tmp[2*HASH_LEN];
    char ig[HASH_LEN];
    char EI[HASH_LEN];
    char L[HASH_LEN];
    char DC[2*HASH_LEN];
    char strFlag[HASH_LEN] = {0};
    Sus stmp; 
    string strK, strV;

    strK = char2str(keyword, keywordlen);
    if(CC.count(strK)>0)
    {
        stmp = CC[strK];

    }else{
        stmp.cu = 0;
        stmp.cs = 0;
        CC.insert(std::make_pair(strK, stmp));
    }
    stmp.cu = stmp.cu + 1;
    CC[strK] = stmp;

    CF(kw, ks, keyword, keywordlen, stmp.cs);
    CF(kw1, ks, keyword, keywordlen, -1);

    CH(hk, kw, stmp.cu);

    strCopy(tmp, strFlag, HASH_LEN);
    CGI(ig, kw1, index, HASH_LEN);
    strCopy(tmp + HASH_LEN, ig, HASH_LEN);

    strXor(tmp, tmp, hk, 2*HASH_LEN);
    strCopy(L, tmp, HASH_LEN);

    strCopy(DC, tmp + HASH_LEN, HASH_LEN);

    AES_E((unsigned char *)EI, (unsigned char *)index, (unsigned char *)kk, HASH_LEN);
    strCopy(DC + HASH_LEN, EI, HASH_LEN);

    redisReply* reply = (redisReply*)redisCommand(conn, Setcomm(L, HASH_LEN, DC, 2*HASH_LEN).c_str());	
	freeReplyObject(reply);
}

void CTrapdoor(int &cu, char *kw, char *ig, char *ks, char *keyword, int keywordlen)
{
    char kw1[HASH_LEN];
    char cNull[HASH_LEN] = {0};
    Sus stmp; 
    string strK, strV;

    strK = char2str(keyword, keywordlen);
    if(CC.count(strK)>0)
    {
        stmp = CC[strK];
        cu = stmp.cu;
        CF(kw, ks, keyword, keywordlen, stmp.cs);
        CF(kw1, ks, keyword, keywordlen, -1);
        CGI(ig, kw1, cNull, HASH_LEN);

    }else{
    printf("no exist trapdoor!\n");
    }
}

void CSearch(int &len, int cu, char *kw, char *ig)
{
    int i;
    char XC[2*HASH_LEN];
    char value[2*HASH_LEN];
    char LD[2*HASH_LEN];
    char L[HASH_LEN];
    char D[HASH_LEN];
    char X[HASH_LEN];

    string strK, strV;
    redisReply* reply;
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    }
    i = cu ; 
    while (i > 0)
    {
        CH(LD, kw, i);
        strCopy(L, LD, HASH_LEN);
        strCopy(D, LD + HASH_LEN, HASH_LEN);
        reply = (redisReply*)redisCommand(conn, Getcomm(L, HASH_LEN).c_str());
        if ( reply->str!= NULL)
		{
            Decode(value, reply->str, reply->len);
            strCopy(XC + HASH_LEN, value + HASH_LEN, HASH_LEN);//copy c
            strXor(X, D, value, HASH_LEN);
            strCopy(XC, X, HASH_LEN);
            strV = char2str(XC, 2*HASH_LEN);
            Cr.insert(std::make_pair(len, strV));
            len++;

        }else{
            printf("error!\n");
            break;
        }
        i--;

    }
    freeReplyObject(reply); 
    redisFree(conn);
}

void CDecrypt(int len, char *kk)
{
    int i = 0;
    char X[HASH_LEN];
    char C[HASH_LEN];
    char XC[2*HASH_LEN];
    char index[HASH_LEN];
    std::map<int, string>::iterator it;
    for (it= Cr.begin(); it != Cr.end(); ++it)
    {
        str2char(XC, it->second);
        strCopy(X, XC, HASH_LEN);
        strCopy(C, XC + HASH_LEN, HASH_LEN);
        AES_D((unsigned char* )index,(unsigned char* ) C, (unsigned char* )kk, HASH_LEN);
        //strPrint(index, HASH_LEN);
        i++;
    }
    if (i == len)
    {
        printf("OK!\n");
        /* code */
    }
    Cr.clear();
}


