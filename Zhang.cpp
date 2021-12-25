#include "Zhang.h"
#include "util.h"
#include <string>


std::map< string,  string> Sigma;
std::map< string,  string> BT;
std::map< int,  string> R;

static char strEOF[32] = {
    (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
 (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
	
void ZKeyGen(char *ks, char *kr)
{
	randomStr(ks, HASH_LEN);
	randomStr(kr, HASH_LEN);
}

void ZUpdate(redisContext* conn, char *ks, char *kr, char *keyword, int keywordlen, char *index, int indexlen)
{
	char tw[HASH_LEN] = {0};
	char rw[HASH_LEN] = {0};

	char st1[HASH_LEN] = {0};
	char st2[HASH_LEN] = {0};

	char tmp3[3*HASH_LEN] = {0};
	char tmp2[2*HASH_LEN] = {0};
	char tmp[HASH_LEN] = {0};
	char e[2*HASH_LEN] = {0};
	
	char hash1[HASH_LEN] = {0};
	char hash2[HASH_LEN] = {0};
	char u[HASH_LEN] = {0};

	string strK, strV;
	int flag = 0;


	ZF1(tw, ks, keyword, keywordlen);
	ZF2(rw, kr, keyword, keywordlen);

	strK = char2str(keyword, keywordlen);

	if (Sigma.count(strK)>0)
	{
		str2char(tmp2, Sigma[strK]);
		strCopy(st1, tmp2, HASH_LEN);
		strCopy(hash2, tmp2 + HASH_LEN, HASH_LEN);

		randomStr(st2, HASH_LEN);
		ZH2(tmp2, tw, st2, HASH_LEN);
		strCopy(e, st1, HASH_LEN);
		strCopy(e + HASH_LEN, index, indexlen);
		strXor(e, tmp2, e, 2*HASH_LEN);

		MulHash(tmp, rw, tw, index);
		HomHash(hash2, rw, tmp, hash2);	//oldhash + H(rw, tw||ind)
		Hash(hash1, rw, st1, HASH_LEN);
		HomHash(hash2, rw, hash2, hash1);// + H(rw, st_{c-1})
		Hash(hash1, rw, st2, HASH_LEN);
		HomHash(hash2, rw, hash2, hash1); //+ H(rw, st_{c-1})
		
	}else{

		randomStr(st2, HASH_LEN);
		ZH2(tmp2, tw, st2, HASH_LEN);
		//EOF||index
		strCopy(e, strEOF, HASH_LEN);
		strCopy(e + HASH_LEN, index, indexlen);
		strXor(e, tmp2, e, 2*HASH_LEN);
		
		MulHash(tmp, rw, tw, index);
		Hash(hash1, rw, st2, HASH_LEN);
		HomHash(hash2, rw, tmp, hash1);
		flag = 1;//the first time;
	}

	strCopy(tmp2, st2, HASH_LEN);
	strCopy(tmp2 + HASH_LEN, hash2, HASH_LEN);
	///\sigma[w] = st2||hash2 
	strK = char2str(keyword, keywordlen);
	strV = char2str(tmp2, 2*HASH_LEN);
	if (flag == 1)
	{
		Sigma.insert(std::make_pair(strK, strV));
	}else{
		Sigma[strK] = strV;
	}
	ZH1(u, tw, st2, HASH_LEN);
	strCopy(tmp3, e, 2*HASH_LEN);
	strCopy(tmp3 + 2*HASH_LEN, hash2, HASH_LEN);
	//BT[u] = e||hash2
	redisReply* reply = (redisReply*)redisCommand(conn, Setcomm(u, HASH_LEN, tmp3, 3*HASH_LEN).c_str());	
	freeReplyObject(reply);

}

//trapdoor = t_w||stc
void ZTrapdoor(char *trapdoor, char *ks, char *keyword, int keywordlen)
{
	char tw[HASH_LEN] = {0};

	char tmp2[2*HASH_LEN] = {0};
	char st2[HASH_LEN] = {0};
	char hash2[HASH_LEN] = {0};
	string strK, strV;

	strK = char2str(keyword, keywordlen);
	if (Sigma.count(strK) > 0)
	{
		str2char(tmp2, Sigma[strK]);
		ZF1(tw, ks, keyword, keywordlen);
		strCopy(trapdoor, tw, HASH_LEN);
		strCopy(trapdoor + HASH_LEN, tmp2, HASH_LEN);
	}else{
		printf("no exist trapdoor!\n");
	}
	
	
}

void ZSearch(int &len,  char *proof, char *trapdoor)
{
	char tw[HASH_LEN] = {0};
	char st2[HASH_LEN] = {0};
	char st1[HASH_LEN] = {0};

	char e[2*HASH_LEN]  = {0};
	char tmp3[3*HASH_LEN] = {0};
	char tmp2[2*HASH_LEN]  = {0};
	char hash2[HASH_LEN] = {0};

	char u[HASH_LEN] = {0};
	char result[HASH_LEN] = {0};

	string strK, strV;
	int index = 0;
	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 


	len = 0;
	strCopy(tw, trapdoor, HASH_LEN);
	strCopy(st2, trapdoor + HASH_LEN, HASH_LEN);
	ZH1(u, tw, st2, HASH_LEN);

	redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
	if ( reply->str!= NULL)
	{
		Decode(tmp3, reply->str, reply->len);
	}else
	{
		freeReplyObject(reply);	
		redisFree(conn);
		printf("the key not in database\n");
		return;
	}
	strCopy(proof, tmp3 + 2*HASH_LEN, HASH_LEN);

	while (!strequal(st2, strEOF, HASH_LEN))
	{
		ZH1(u, tw, st2, HASH_LEN);
	
		reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
		if ( reply->str!= NULL)
		{
			Decode(tmp3, reply->str, reply->len);
		}else
		{
			freeReplyObject(reply);	
			redisFree(conn);
			printf("the key not in database\n");
			return;
		}
		strCopy(e, tmp3, 2*HASH_LEN);
		//Xor 
		ZH2(tmp2, tw, st2, HASH_LEN);
		strXor(tmp2, e, tmp2, 2*HASH_LEN);
		strCopy(st2, tmp2, HASH_LEN);
		strCopy(result, tmp2 + HASH_LEN, HASH_LEN);
		strV = char2str(result, HASH_LEN);
		//store the R set.
		R.insert(std::make_pair(len, strV));
		len++;
	}
	freeReplyObject(reply);	
	redisFree(conn);
	
}

void ZSearchE(int &len, char *proof,  char *trapdoor)
{
	char tw[HASH_LEN] = {0};
	char st2[HASH_LEN] = {0};
	char st1[HASH_LEN] = {0};

	char e[2*HASH_LEN]  = {0};
	char tmp3[3*HASH_LEN] = {0};
	char tmp2[2*HASH_LEN]  = {0};
	char hash2[HASH_LEN] = {0};
	char result[HASH_LEN] = {0};
	char u[HASH_LEN] = {0};

	string strK, strV;
	int index = 0;
	len = 0;
	strCopy(tw, trapdoor, HASH_LEN);
	strCopy(st2, trapdoor + HASH_LEN, HASH_LEN);
	ZH1(u, tw, st2, HASH_LEN);
	strK = char2str(u, HASH_LEN);
	str2char(tmp3, BT[strK]);
	strCopy(proof, tmp3 + 2*HASH_LEN, HASH_LEN);

	while (!strequal(st2, strEOF, HASH_LEN))
	{
		ZH1(u, tw, st2, HASH_LEN);
		strK = char2str(u, HASH_LEN);
		str2char(tmp3, BT[strK]);
		strCopy(e, tmp3, 2*HASH_LEN);
		//Xor 
		ZH2(tmp2, tw, st2, HASH_LEN);
		strXor(tmp2, e, tmp2, 2*HASH_LEN);
		strCopy(st2, tmp2, HASH_LEN);
		strCopy(result, tmp2 + HASH_LEN, HASH_LEN);
		strV = char2str(result, HASH_LEN);
		//store the R set.
		R.insert(std::make_pair(len, strV));
		len++;
		//printf("--%d--\n", len);
	}
	
}
// st_c, st_{c-1}
void ZVerify(char *result,int len, char *proof, char *ks, char *kr, char *keyword, int keywordlen)
{
	char rw[HASH_LEN] = {0};
	char tw[HASH_LEN] = {0};

	char tmp2[2*HASH_LEN] = {0};
	char tmp[HASH_LEN] = {0};
	
	char st2[HASH_LEN] = {0};
	char hash2[HASH_LEN] = {0};
	char hash1[HASH_LEN] = {0};
	char index[HASH_LEN] = {0};
	string strK;
	int i;

	
	strK = char2str(keyword, keywordlen);
	if (Sigma.count(strK) > 0)
	{
		str2char(tmp2, Sigma[strK]);
		strCopy(st2, tmp2, HASH_LEN);
		strCopy(hash1, tmp2 + HASH_LEN, HASH_LEN);///the latest hash'
		ZF1(tw, ks, keyword, keywordlen);	
		ZF2(rw, kr, keyword, keywordlen);
 		 
		Hash(hash2, rw, st2, HASH_LEN);//
		for (i = 0; i < len; i++)
		{
			strCopy(index, result + i*HASH_LEN, HASH_LEN);
			MulHash(tmp, rw, tw, index);
			HomHash(hash2, rw, tmp, hash2);
		}
		if (strequal(proof, hash1, HASH_LEN)&&strequal(proof, hash2, HASH_LEN))
		{
			printf("verify successfull!\n");
			return;
		}
		printf("verify failed!\n");
	}
}

void ZVerifyE(int len, char *proof, char *ks, char *kr, char *keyword, int keywordlen)
{
	char rw[HASH_LEN] = {0};
	char tw[HASH_LEN] = {0};

	char tmp2[2*HASH_LEN] = {0};
	char tmp[HASH_LEN] = {0};
	
	char st2[HASH_LEN] = {0};
	char hash2[HASH_LEN] = {0};
	char hash1[HASH_LEN] = {0};
	char index[HASH_LEN] = {0};

	char result[HASH_LEN] = {0};	
	string strK;
	int i;

	
	strK = char2str(keyword, keywordlen);
	if (Sigma.count(strK) > 0)
	{
		str2char(tmp2, Sigma[strK]);
		strCopy(st2, tmp2, HASH_LEN);
		strCopy(hash1, tmp2 + HASH_LEN, HASH_LEN);///the latest hash'
		ZF1(tw, ks, keyword, keywordlen);	
		ZF2(rw, kr, keyword, keywordlen);
 		 
		Hash(hash2, rw, st2, HASH_LEN);//
		for (i = 0; i < len; i++)
		{
			str2char(result, R[i]);
			strCopy(index, result, HASH_LEN);
			MulHash(tmp, rw, tw, index);
			HomHash(hash2, rw, tmp, hash2);
		}
		if (strequal(proof, hash1, HASH_LEN)&&strequal(proof, hash2, HASH_LEN))
		{
			printf("verifyE successfull!\n");
			return;
		}
		printf("verifyE failed!\n");
	}
}