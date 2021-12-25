#include "he.h"
#include "util.h"
#include <string>



std::map< string,  string> HKW;
std::map< string,  string> HDic;
std::map< int,  string> Hr;
char strNull[32] = {
    (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
 (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };

void HKeyGen(char *ks)
{
    randomStr(ks, HASH_LEN);
}

void SubUpdata(char *st, char *index, int indexlen)
{
    char key[HASH_LEN];
    char value[2*HASH_LEN];
    char tmp1[2*HASH_LEN];
    char tmp2[2*HASH_LEN];
    char rt[HASH_LEN];

    string strK, strV;

    h(key, st, HASH_LEN, 0);

    strK = char2str(key, HASH_LEN);
    if (HDic.count(strK)>0)
	{
        str2char(value, HDic[strK]);
        randomStr(rt, HASH_LEN);

        HH(tmp1, st, HASH_LEN);
        strCopy(tmp2, index, indexlen);
        strCopy(tmp2 + indexlen, rt, HASH_LEN);

        strXor(tmp1, tmp1, tmp2, 2*HASH_LEN);
        strV= char2str(tmp1, 2*HASH_LEN);
        HDic[strK] = strV;//insert.

        h(key, rt, HASH_LEN, 0);
        strK = char2str(key, HASH_LEN);
        HH(tmp1, rt, HASH_LEN);
        HH(tmp2, st, HASH_LEN);
        strXor(tmp1, tmp1, tmp2, 2*HASH_LEN);
        strXor(value, value, tmp1, 2*HASH_LEN);
        strV = char2str(value, 2*HASH_LEN);
        HDic.insert(std::make_pair(strK, strV));

    }else{
        HH(tmp1, st, HASH_LEN);
        strCopy(value, index, indexlen);
        strCopy(value + indexlen, strNull, HASH_LEN);
        strXor(value, tmp1, value, 2*HASH_LEN);
        strV = char2str(value, 2*HASH_LEN);
        HDic.insert(std::make_pair(strK, strV));
    }
    return;

}

void HUpdate(redisContext* conn, char *ks, int &crt, char *W, int keywordlen, int wL, int fn,  char *sIndex)
{
    int i, j;
    char st[HASH_LEN];
    char kt[HASH_LEN];
    char u[HASH_LEN];
    char e[2*HASH_LEN];
    
    std::map<string, string>::iterator  it;
    string strK, strV;

    for ( i = 0; i < wL; i++)
    {
        W[0] = i;
        strK = char2str(W, keywordlen);
        if (HKW.count(strK)>0) 
        {
            str2char(st, HKW[strK]);
        }else{
            HF(kt, ks, HASH_LEN, W, keywordlen);
            HHF(st, kt, HASH_LEN, crt);
            HDic.clear();
        } 
        for ( j = 0; j < fn; j++)
        {
            sIndex[0] = j;
            SubUpdata(st, sIndex, HASH_LEN);
            /* code */
        }
        for ( it= HDic.begin(); it != HDic.end(); ++it)
        {
            str2char(u, it->first);
            str2char(e, it->second);

            redisReply* reply = (redisReply*)redisCommand(conn, Setcomm(u, HASH_LEN, e, 2*HASH_LEN).c_str());	
	        freeReplyObject(reply);
            /* code */
        }
        HDic.clear();

    }
    crt = crt -1;

}

void HTrapdoor(char* trapdoor, int crt, char *ks, char *keyword, int keywordlen)
{
    char kt[HASH_LEN];
    HF(kt, ks, HASH_LEN, keyword, keywordlen);
    HHF(trapdoor, kt, HASH_LEN, crt);

}

void HSearch(int &len, char *trapdoor, int Clen, int crt)
{
    int j;
    char key[HASH_LEN];
    char st[HASH_LEN];
    char value[2*HASH_LEN];
    char tmp1[2*HASH_LEN];
    char index[HASH_LEN];
    char rt[HASH_LEN];

    string strV;
    redisReply* reply;
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    }
    j = crt;
    strCopy(st, trapdoor, HASH_LEN);
    while (j <= Clen)
    {     
        h(key, st, HASH_LEN, 0);
        reply = (redisReply*)redisCommand(conn, Getcomm(key, HASH_LEN).c_str());
        if ( reply->str!= NULL)
		{
			Decode(value, reply->str, reply->len);
            HH(tmp1, st, HASH_LEN);
            strXor(value, value, tmp1, 2*HASH_LEN);
            strCopy(index, value, HASH_LEN);
            strCopy(rt, value + HASH_LEN, HASH_LEN);
            strV = char2str(index, HASH_LEN);
            Hr.insert(std::make_pair(len, strV));//
            len++;
            while (!strequal(rt, strNull, HASH_LEN))
            {
                h(key, rt, HASH_LEN, 0);
                reply = (redisReply*)redisCommand(conn, Getcomm(key, HASH_LEN).c_str());
                Decode(value, reply->str, reply->len);
                HH(tmp1, rt, HASH_LEN);
                strXor(value, value, tmp1, 2*HASH_LEN);
                strCopy(index, value, HASH_LEN);
                strCopy(rt, value + HASH_LEN, HASH_LEN);
                strV = char2str(index, HASH_LEN);
                Hr.insert(std::make_pair(len, strV));//   
                len++;            
            }
		}
        j = j+1;
        HHI(st, st);
    }
    freeReplyObject(reply); 
    redisFree(conn);
}
