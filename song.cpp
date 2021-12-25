#include "song.h"
#include "util.h"
#include <string>
#include "aes.h"

std::map< string,  string> Ssigma;
std::map< int,  string> Sr;

char strSt0[32] = {
    (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
 (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
void SKeyGen(char *ks)
{
    randomStr(ks, HASH_LEN);
}

void SUpdate(redisContext* conn, char *ks, char *keyword, int keywordlen, char *index, int indexlen)
{
    char htmp[HASH_LEN];
    char tw[HASH_LEN];

    char st0[HASH_LEN];
    char st1[HASH_LEN];
    char value[HASH_LEN + 4];
    char key[HASH_LEN];
    char EI[HASH_LEN];
    char strH2[2*HASH_LEN];
    char e[2*HASH_LEN];
    char u[HASH_LEN];
    
	string strK, strV;
    int count;
    int flag = 0;

    gh(htmp, keyword, keywordlen);
    SF(tw, ks, HASH_LEN, htmp, HASH_LEN);//tw = F(ks,h(w))

	strK = char2str(keyword, keywordlen);
    //(st_0, 0)
    if (Ssigma.count(strK)>0)
	{
        str2char(value, Ssigma[strK]);
        count = char2int(value, 4);
        strCopy(st0, value + 4, HASH_LEN);

    }else{
        strCopy(st0, strSt0, HASH_LEN);
        count = 0;
        flag = 1;

    }
    randomStr(key, HASH_LEN);
    count = count + 1;
    AES_E((unsigned char *)st1, (unsigned char *)st0 , (unsigned char *)key, HASH_LEN);
    int2char(value, count);
    strCopy(value + 4, st1, HASH_LEN);
    //[w] = (st1, c+1);
    strV = char2str(value, HASH_LEN+4);
    if (flag == 1)
    {
       	Ssigma.insert(std::make_pair(strK, strV));
    }else{
        Ssigma[strK] = strV;
    }
    //
    SH2(strH2, tw, st1, HASH_LEN);
    strCopy(e, index, indexlen);
    strCopy(e + indexlen, key, HASH_LEN);
    strXor(e, e, strH2, 2*HASH_LEN);
    //
    SH1(u, tw, st1, HASH_LEN);
    //(u,e)
    redisReply* reply = (redisReply*)redisCommand(conn, Setcomm(u, HASH_LEN, e, 2*HASH_LEN).c_str());	
	freeReplyObject(reply);
}

void STrapdoor(char* trapdoor, int &count, char *ks, char *keyword, int keywordlen)
{
    char htmp[HASH_LEN];
    char tw[HASH_LEN];
    char value[HASH_LEN + 4];

	string strK, strV;

    gh(htmp, keyword, keywordlen);
    SF(tw, ks, HASH_LEN, htmp, HASH_LEN);//tw = F(ks,h(w))

    strK = char2str(keyword, keywordlen);
    //(st_0, 0)
    if (Ssigma.count(strK)>0)
	{
        str2char(value, Ssigma[strK]);
        count = char2int(value, 4);
        strCopy(trapdoor, tw, HASH_LEN);
        strCopy(trapdoor + HASH_LEN, value + 4, HASH_LEN);

    }else{
        printf("no exist trapdoor!\n");
    }

}

void SSearch(int &len, char *trapdoor, int count)
{
    int i;
    char tw[HASH_LEN];
    char st1[HASH_LEN];
    char st0[HASH_LEN];
    char tmp2[2*HASH_LEN];
    char e[2*HASH_LEN];
    char u[HASH_LEN];
    char key[HASH_LEN];
    char index[HASH_LEN];

    redisReply* reply;
	string strK, strV;

    strCopy(tw, trapdoor, HASH_LEN);
    strCopy(st1, trapdoor + HASH_LEN, HASH_LEN);

	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 


    for ( i = count; i > 0; i--)
    {
        SH1(u, tw, st1, HASH_LEN);
        reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
        if ( reply->str!= NULL)
		{
			Decode(e, reply->str, reply->len);
		}else
		{
			freeReplyObject(reply);	
			redisFree(conn);
			printf("the key not in database\n");
			return;
		}
        SH2(tmp2, tw, st1, HASH_LEN);
        strXor(tmp2, tmp2, e, 2*HASH_LEN);
        strCopy(index, tmp2, HASH_LEN);
        strCopy(key, tmp2 + HASH_LEN, HASH_LEN);
        AES_D((unsigned char* )st0,(unsigned char* ) st1, (unsigned char* )key, HASH_LEN);
        strCopy(st1, st0, HASH_LEN);
        strV = char2str(index, HASH_LEN);
        if(Sr.count(len) > 0)
		{
			Sr[len] = strV;

		}else{
			Sr.insert(std::make_pair(len, strV));//
		}
	
        len++;
    }
    redisFree(conn);
	return;
}