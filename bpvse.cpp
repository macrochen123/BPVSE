#include <stdio.h>
#include "bpvse.h"
#include "curve_para.h"
#include "util.h"
#include <string>
#include "aes.h"
#include <hiredis/hiredis.h>
#include <pthread.h>


/**
 * @brief these are the global parameter, such the elliptic curve paramerters, a struct, and an initial state EOF.
 * 
 */
big Gx, Gy, p, a, b;
big Curve_N;
epoint *Curve_G;
big g_ONE, g_ZERO;

struct para{
int iDB;
string st1;
string st2;
string pv2;
int id;
};

char strEOF[32] = {
    (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
 (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
/**
 * @brief The map to store some state information
 * 
 */

std::map< int,  string> TR;
std::map< int,  int> RN;
std::map< int,  string> SR;

std::map< int,  string> T1;
std::map< string,  string> T2;
std::map< int,  string> T3;
std::map< string,  string> T4;
std::map< string,  string> T5;


int Curve_Init()
{
	/*********************/
	miracl *mip;
    epoint *nG;
	/*********************/
    /* Init configurations of Miracl library */
	mip = mirsys(10000, 16);
	mip->IOBASE = 16;

	Gx = mirvar(0);
	Gy = mirvar(0);
	p = mirvar(0);
	a = mirvar(0);
	b = mirvar(0);
	Curve_N = mirvar(0);
	Curve_G = epoint_init();
	nG = epoint_init();
	g_ZERO = mirvar(0);
	g_ONE = mirvar(1);
    /* Init all params for SM2 algorithm */
	if(CURVE_SIZE == 32)
	{
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_P, p);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_A, a);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_B, b);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_N, Curve_N);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_Gx, Gx);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_256_Gy, Gy);
	}else
	{
		/* code */
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_160_P, p);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_160_A, a);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_160_B, b);
		bytes_to_big(CURVE_SIZE+1, (char *)g_Curve_160_N, Curve_N);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_160_Gx, Gx);
		bytes_to_big(CURVE_SIZE, (char *)g_Curve_160_Gy, Gy);
	}
	
	//projective coordinate
	ecurve_init(a, b, p, MR_PROJECTIVE);

    /* Check the G initialise point is valid */
	if (!epoint_set(Gx, Gy, 0, Curve_G))
		return ERR_ECURVE_INIT;

	ecurve_mult(Curve_N, Curve_G, nG);
	if (!point_at_infinity(nG)) //test if the order of the point is n
		return ERR_ECURVE_INIT;

	epoint_free(nG);

	return 0;
}

//generate public/private key
void KeyGen(epoint *kP, big k)
{
   ecurve_mult(k, Curve_G, kP);
}


int UPdate(char *stl, char *ckey, int l, char *W, int *DB, int wL, char *sIndex)
{
	/************************************/
	char sDB[HASH_LEN+4];
	char v1[HASH_LEN];
	char v2[HASH_LEN];

	char st1[HASH_LEN];
	char st2[HASH_LEN];

	char Pa1[HASH_LEN];
	char Pv1[HASH_LEN];

	char Pa2[HASH_LEN];
	char Pv2[HASH_LEN];

	char Sv1[HASH_LEN+4];
	char Sa1[HASH_LEN];

	char sk[HASH_LEN];
	char EI[HASH_LEN];
	char IH[HASH_LEN] = {0};

	char Ia[HASH_LEN];
	char Iv[HASH_LEN];

	char hd[HASH_LEN];

	int i, j;

	string str;
	string strK;
	string strV;
	/************************************/
	/*connect the Redis dataset*/
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
	/*set the index of version information, this is a increment variant*/
	l = l + 1;//setup: i = 0
	redisReply* reply = (redisReply*)redisCommand(conn, GetcommInt(l-1).c_str());//T1
	if (reply->str != NULL)
	{
		/* recovery the previous version */
		Decode(v1, reply->str, reply->len);
	}else{
		strCopy(v1, strEOF, HASH_LEN);
	}
	/*select a new version*/
	randomStr(v2, HASH_LEN);
	for ( i = 0; i < wL; i++)
	{
		W[0] = i;
		if (!strequal(v1, strEOF, HASH_LEN))
		{
			F1(st1, W, WORD_LEN, v1, ckey, 1); 
			/* code */
		}else{
			strCopy(st1, strEOF, HASH_LEN);
			h(Pa1, st1, HASH_LEN, 0);
			reply = (redisReply*)redisCommand(conn, Setcomm(Pa1, HASH_LEN, strEOF, HASH_LEN).c_str());
		
		}
		h(Pa1, st1, HASH_LEN, 0);
		reply = (redisReply*)redisCommand(conn, Getcomm(Pa1, HASH_LEN).c_str());
		if (reply->str != NULL)
		{
			Decode(Pv1, reply->str, reply->len);
		}	

		F1(st2, W, WORD_LEN, v2, ckey, 1); 
		h(Sa1, st2, HASH_LEN, 1);
		h2(Sv1, st2, HASH_LEN);
		int2char(sDB, DB[0]);
		strCopy(sDB+4, st1, HASH_LEN);
		strXor(Sv1, Sv1, sDB, HASH_LEN+4); 
	    F1(sk, W, WORD_LEN, v2, ckey, 2); 
		Reset(IH, HASH_LEN);
		for ( j = 0; j < DB[0]; j++)
		{
			randomStr(sIndex, HASH_LEN); //new index, for the test
			AES_E((unsigned char *)EI, (unsigned char *)sIndex , (unsigned char *)sk, HASH_LEN); //encrypt the indexes
			addHash(IH, IH, EI, HASH_LEN);
			h34(Ia, st2, HASH_LEN, j, 3);
			h34(Iv, st2, HASH_LEN, j, 4);
			strXor(Iv, Iv, EI, HASH_LEN);
			/*insert(Ia, Iv)*/
			reply = (redisReply*)redisCommand(conn, Setcomm(Ia, HASH_LEN, Iv, HASH_LEN).c_str());
			if(NULL == reply)
        	{
          	  printf("get to redis failed ...\n");
        	}

			
		}
		strCopy(hd, IH, HASH_LEN);

		h(Pa2, st2, HASH_LEN, 0);
printf("st\n");
strPrint(Pa2, HASH_LEN);
		hkey(Pv2, hd, Pv1, HASH_LEN, st2, HASH_LEN);		
		///insert (Pa, Pv)
		reply = (redisReply*)redisCommand(conn, Setcomm(Pa2, HASH_LEN, Pv2, HASH_LEN).c_str());
		if(NULL == reply)
		{
			printf("get to redis failed-(pa,pv) ...\n");
		}	
		///insert (Sa, Sv)
		reply = (redisReply*)redisCommand(conn, Setcomm(Sa1, HASH_LEN, Sv1, HASH_LEN+4).c_str());
		if(NULL == reply)
		{
			printf("get to redis failed (Sa, Sv) ...\n");
		}		
	}

	//insert(l, version)
	reply = (redisReply*)redisCommand(conn, SetcommInt(l, v2, HASH_LEN).c_str());
	freeReplyObject(reply);
	strCopy(stl, v2, HASH_LEN);
    redisFree(conn);
    return l;
}

void Trapdoor(char *trapdoor, char *ckey, int l, char *keyword, int wordLen)
{
	string str;
	char v1[HASH_LEN];
	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

	redisReply* reply = (redisReply*)redisCommand(conn, GetcommInt(l).c_str());
	if (reply->str != NULL)
	{
		Decode(v1, reply->str, reply->len);
	
	}else{
		printf("version error!\n");
		return;
	}
	
	F1(trapdoor, keyword, wordLen, v1, ckey, 1); 

	freeReplyObject(reply);	
	redisFree(conn);
}

int Search(int &resultLen, int &astLen,  char *Trapdoor)
{
	char IH[HASH_LEN] = {0};
	char st2[HASH_LEN];
	char u[HASH_LEN];
	char Pv2[HASH_LEN];
	char Pv2T[HASH_LEN];
	char Pv1[HASH_LEN];

	char Sa[HASH_LEN];
	char Sv[HASH_LEN+4];
	char tmp1[HASH_LEN+4];

	char sDB[4];
	int iDB;
	char st1[HASH_LEN];

	char Ia[HASH_LEN];
	char Iv[HASH_LEN+4];

	char EI[HASH_LEN];
	char hd[HASH_LEN];

	int i;

	int version= -1;
	string strK, strV;
	resultLen = 0;
	
	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

	strCopy(st2, Trapdoor, HASH_LEN);
	h(u, st2, HASH_LEN, 0);
	redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
	if ( reply->str!= NULL)
	{
		Decode(Pv2, reply->str, reply->len);		
		version = 0;
		astLen = 0;
		
		while (!strequal(st2, strEOF, HASH_LEN))
		{
			h(Sa, st2, HASH_LEN, 1);
		
			reply = (redisReply*)redisCommand(conn, Getcomm(Sa, HASH_LEN).c_str());
			Decode(Sv, reply->str, reply->len);
			h2(tmp1, st2, HASH_LEN);
			strXor(tmp1, Sv, tmp1, HASH_LEN+4);
			strCopy(sDB, tmp1, 4);
			strCopy(st1, tmp1+4, HASH_LEN);
			iDB = char2int(sDB, 4);
			Reset(IH, HASH_LEN);
			for ( i = 0; i < iDB; i++)
			{
				h34(Ia, st2, HASH_LEN, i, 3);
				//get method
				reply = (redisReply*)redisCommand(conn, Getcomm(Ia, HASH_LEN).c_str());
				Decode(EI, reply->str, reply->len);
				h34(Iv, st2, HASH_LEN, i, 4);
				strXor(EI, Iv, EI, HASH_LEN);
				addHash(IH, IH, EI, HASH_LEN);
				//record the returned result
				strV = char2str(EI, HASH_LEN);
				TR.insert(std::make_pair(resultLen, strV));
				resultLen++;
			//	printf("--%d--\n", resultLen);

			}
			strCopy(hd, IH, HASH_LEN);

			h(u, st1, HASH_LEN, 0);
printf("u:\n");
strPrint(u, HASH_LEN);	
			reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
			if(reply->str != NULL)
			{
				Decode(Pv1, reply->str, reply->len);
			}else{

				printf("Recover error-1!\n");
				freeReplyObject(reply);	
				redisFree(conn);
				return -1;
			}
			
			hkey(Pv2T, hd, Pv1, HASH_LEN, st2, HASH_LEN);
			if(!strequal(Pv2, Pv2T, HASH_LEN))
			{
				printf("Recover error-2!\n");
				freeReplyObject(reply);	
				redisFree(conn);
				return -1;
			}	
			RN.insert(std::make_pair(version, iDB));//
			strV= char2str(st2, HASH_LEN);

			SR.insert(std::make_pair(astLen, strV));//
			strCopy(st2, st1, HASH_LEN);
			strCopy(Pv2, Pv1, HASH_LEN);
			version++;
			astLen++;
		}
	}
	freeReplyObject(reply);	
	redisFree(conn);
	return version;
}

bool Verify(int resultLen, int astLen)
{
	int i,j;
	int index;
	int tmpR;

	char IH[HASH_LEN] = {0};
	char hd[HASH_LEN];
	char tmp[HASH_LEN];
	char st[HASH_LEN];
	char Pv1[HASH_LEN];
	char Pv2[HASH_LEN];
	char Pv2T[HASH_LEN];
	
	index  = resultLen;
	string str;

	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

	strCopy(Pv1, strEOF, HASH_LEN);
	str2char(st, SR[astLen-1]);//st_1
	tmpR = RN[astLen-1];
	for(i = 0; i < tmpR; i++)
	{
		str2char(tmp, TR[index-tmpR+i]);
		addHash(IH, IH, tmp, HASH_LEN);
	}
	
	strCopy(hd, IH, HASH_LEN);
	hkey(Pv2, hd, Pv1, HASH_LEN, st, HASH_LEN); 

	index = resultLen - tmpR;
	for ( i = astLen- 2; i >= 0; i--)
	{
		strCopy(Pv1, Pv2, HASH_LEN);
		str2char(st, SR[i]);//st_2,3,4,....,	
		tmpR = RN[i];
		Reset(IH, HASH_LEN);
		for(j = 0; j < tmpR; j++)
		{
			str2char(tmp, TR[index-tmpR+j]);
			addHash(IH, IH, tmp, HASH_LEN);
		}
		strCopy(hd, IH, HASH_LEN);
		hkey(Pv2, hd, Pv1, HASH_LEN, st, HASH_LEN); 
		index = index - tmpR;
	}
	str2char(st, SR[0]);
	h(tmp, st, HASH_LEN, 0);
	redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(tmp, HASH_LEN).c_str());
	if ( reply->str!= NULL)
	{
		Decode(Pv2T, reply->str, reply->len);
	}else{
		printf("verify-error!\n");
		freeReplyObject(reply);	
		redisFree(conn);
		return false;
	}

	if (strequal(Pv2, Pv2T, HASH_LEN))
	{
		freeReplyObject(reply);	
	    redisFree(conn);
		return true;
	}
	freeReplyObject(reply);	
	redisFree(conn);
	return false;
}

void Decryption(char *Message, int & outputlen, char *ckey, char *result, int resultLen, int *aRlen, char *aVer, int averLen, char *keyword, int wordLen)
{
	char tmp[HASH_LEN];
	char sk[HASH_LEN];
	char strV[HASH_LEN];

	int i, j;
	int index = 0;
	//
	for (i = 0; i < averLen; i++)//v_l, v_{l-1}, ...
	{
		strCopy(strV, aVer + (averLen- i -1)*HASH_LEN, HASH_LEN);
		F1(sk, keyword, wordLen, strV, ckey, 2); 
		for ( j = 0; j <  aRlen[i]; j++)
		{
			strCopy(tmp, result +  index +  j *HASH_LEN, HASH_LEN);//R_{v_1}||R_{v_2}
			AES_D((unsigned char* )(Message+index + j*HASH_LEN),(unsigned char* ) tmp, (unsigned char* )sk, HASH_LEN);
			/* code */
		}
		index  = index + aRlen[i]*HASH_LEN;
	}
	outputlen = index;
}

void GetKey(char *ckey, epoint *PK, big sk)
{	
	epoint *keyPoint;
	big x, y;
	char tmp2[HASH_LEN*2];

	keyPoint = epoint_init();
	x = mirvar(0);
	y = mirvar(0);
	ecurve_mult(sk, PK, keyPoint);
	epoint_get(keyPoint, x, y);
	big_to_bytes(HASH_LEN, x, tmp2, TRUE);
	big_to_bytes(HASH_LEN, y, tmp2 + HASH_LEN, TRUE);
	gh(ckey, tmp2, HASH_LEN*2);
	mirkill(x); mirkill(y);
	epoint_free(keyPoint); 
}



///T1 ---the update time,  T2, T5, the number of index, the number of keywords
int TUPdate(char *stl, char *ckey, int l, char *W, int *DB, int wL, char *sIndex)
{

	char sDB[HASH_LEN+4];

	char v1[HASH_LEN];
	char v2[HASH_LEN];

	char st1[HASH_LEN];
	char st2[HASH_LEN];

	char Pa1[HASH_LEN];
	char Pv1[HASH_LEN];
	char Pa2[HASH_LEN];
	char Pv2[HASH_LEN];

	char Sv1[HASH_LEN+4];
	char Sa1[HASH_LEN];

	char sk[HASH_LEN];
	char EI[HASH_LEN];
	char IH[HASH_LEN] = {0};

	char Ia[HASH_LEN];
	char Iv[HASH_LEN];

	char hd[HASH_LEN];

	int i, j;
	int index;
	string str;
	string strK;
	string strV;
///////////////////////////////////

	l = l + 1;//setup: i = 0
	if (T1.count(l-1) > 0)
	{
		str = T1[l-1];
		str2char(v1, str);
		/* code */
	}else{
		strCopy(v1, strEOF, HASH_LEN);
	}
	randomStr(v2, HASH_LEN);
	index = 0;
	//T2, T5
	for ( i = 0; i < wL; i++)
	{
		W[0] = i;
		if (!strequal(v1, strEOF, HASH_LEN))
		{
			//F1(st1, W+i*WORD_LEN, WORD_LEN, v1, ckey, 1); 
			F1(st1, W, WORD_LEN, v1, ckey, 1); 
			/* code */
		}else{
			strCopy(st1, strEOF, HASH_LEN);
			h(Pa1, st1, HASH_LEN, 0);
			strK = char2str(Pa1, HASH_LEN);
			strV = char2str(strEOF, HASH_LEN);
			T2.insert(std::make_pair(strK, strV)); ///st0--U
		}
		h(Pa1, st1, HASH_LEN, 0);
		str = char2str(Pa1, HASH_LEN);
		if (T2.count(str) > 0)
		{
			str2char(Pv1, T2[str]);
		}		
	//	F1(st2, W+i*WORD_LEN, WORD_LEN, v2, ckey, 1); 
		F1(st2, W, WORD_LEN, v2, ckey, 1); 

		h(Sa1, st2, HASH_LEN, 1);
		h2(Sv1, st2, HASH_LEN);
		///the number of index
		DB[0] = DB[0];
		int2char(sDB, DB[0]);
		//int2char(sDB, DB[i]);

		strCopy(sDB+4, st1, HASH_LEN);
		strXor(Sv1, Sv1, sDB, HASH_LEN+4); 
		
	    //F1(sk, W+i*WORD_LEN, WORD_LEN, v2, ckey, 2); 
		F1(sk, W, WORD_LEN, v2, ckey, 2); 
		Reset(IH, HASH_LEN);
		for ( j = 0; j < DB[i]; j++)
		{
			sIndex[0] = j;
			AES_E((unsigned char *)EI, (unsigned char *)sIndex , (unsigned char *)sk, HASH_LEN); //for text, each index is the same
			addHash(IH, IH, EI, HASH_LEN);
			h34(Ia, st2, HASH_LEN, j, 3);
			h34(Iv, st2, HASH_LEN, j, 4);
			strXor(Iv, Iv, EI, HASH_LEN);
			index = index + HASH_LEN;
			//insert(Ia, Iv)
			strK = char2str(Ia, HASH_LEN);
			strV = char2str(Iv, HASH_LEN);
			//do insert data
			//T5.insert(std::make_pair(strK, strV));
		
		}
		strCopy(hd, IH, HASH_LEN);
		h(Pa2, st2, HASH_LEN, 0);
		hkey(Pv2, hd, Pv1, HASH_LEN, st2, HASH_LEN);
		///insert (Pa, Pv)
		strK = char2str(Pa2, HASH_LEN);
		strV = char2str(Pv2, HASH_LEN);
		T2.insert(std::make_pair(strK, strV));
		///insert (Sa, Sv)
		strK = char2str(Sa1, HASH_LEN);
		strV = char2str(Sv1, HASH_LEN+4);
		//T5.insert(std::make_pair(strK, strV));
	}
	str = char2str(v2, HASH_LEN);
	//insert(l, version)
	T1.insert(std::make_pair(l, str));
	strCopy(stl, v2, HASH_LEN);

    return l;
}

void *SearchCore(void *data)
{
	struct para *d = (struct para*)data;

	int i;
	char st1[HASH_LEN] = {0};
	char st2[HASH_LEN] = {0};
	char Ia[HASH_LEN] = {0};
	char Iv[HASH_LEN] = {0};
	char EI[HASH_LEN] = {0};
	char IH[HASH_LEN] = {0};
	char u[HASH_LEN] = {0};
	char hd[HASH_LEN] = {0};
	char Pa1[HASH_LEN] = {0};
	char Pv1[HASH_LEN] = {0};
	char Pa2[HASH_LEN] = {0};
	char Pv2[HASH_LEN] = {0};
	char Pv2T[HASH_LEN] = {0};

	int resultLen = 0;
	int iDB;
	int id;
	string strV;
	string sst1, sst2, spv;

	sst1 = d->st1;
	sst2 = d->st2;
	spv = d->pv2;
	iDB = d->iDB;
	id = d->id;

	str2char(st1, sst1);
	str2char(st2, sst2);
	str2char(Pv2, spv);

printf("st1,2--input:%d\n", id);
strPrint(st1, HASH_LEN);
strPrint(st2, HASH_LEN);

	resultLen = id*iDB;
	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
	for ( i = 0; i < iDB; i++)
	{
		h34(Ia, st2, HASH_LEN, i, 3);
		//get method
		redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(Ia, HASH_LEN).c_str());
		Decode(EI, reply->str, reply->len);
		h34(Iv, st2, HASH_LEN, i, 4);
		strXor(EI, Iv, EI, HASH_LEN);
		addHash(IH, IH, EI, HASH_LEN);
		//record the returned result
		strV = char2str(EI, HASH_LEN);
		if(TR.count(resultLen) > 0)
		{
			TR[resultLen]=strV;
		}else{
			TR.insert(std::make_pair(resultLen, strV));
		}
		
		resultLen++;
		
		freeReplyObject(reply);	
	}
	strCopy(hd, IH, HASH_LEN);

	h(u, st1, HASH_LEN, 0);
	
	redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
	if(reply->str != NULL)
	{
		Decode(Pv1, reply->str, reply->len);
	}else{
		printf("Recover error-1-%d!, , result = %d\n", id, resultLen);
		freeReplyObject(reply);	
		redisFree(conn);
		return NULL;
	}
	
	hkey(Pv2T, hd, Pv1, HASH_LEN, st2, HASH_LEN);
	if(!strequal(Pv2, Pv2T, HASH_LEN))
	{
		printf("Recover error-2-%d!, result = %d\n", id, resultLen);
		freeReplyObject(reply);	
		redisFree(conn);
		return NULL;
	}	
	redisFree(conn);
	
	printf("thread-%d: %d\n", id, resultLen);
	
	
}



void MultiSearch(int &resultLen, int &astLen,  char *Trapdoor)
{
	char IH[HASH_LEN] = {0};
	char st2[HASH_LEN];
	char u[HASH_LEN];
	char Pv2[HASH_LEN];
	char Pv2T[HASH_LEN];
	char Pv1[HASH_LEN];

	char Sa[HASH_LEN];
	char Sv[HASH_LEN+4];
	char tmp1[HASH_LEN+4];

	char sDB[4];
	int iDB;
	char st1[HASH_LEN];

	char Ia[HASH_LEN];
	char Iv[HASH_LEN+4];

	char EI[HASH_LEN];
	char hd[HASH_LEN];

	int i;
	int threadID = 0;

	int version= -1;
	para d[5];
	
	
	string strK, strV;
	pthread_t tids[NUM_THREADS];

	resultLen = 0;
	
	redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

	strCopy(st2, Trapdoor, HASH_LEN);
	h(u, st2, HASH_LEN, 0);
	redisReply* reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
	if ( reply->str!= NULL)
	{
		Decode(Pv2, reply->str, reply->len);		
		version = 0;
		astLen = 0;
		
		while (!strequal(st2, strEOF, HASH_LEN))
		{
			
			h(Sa, st2, HASH_LEN, 1);
			reply = (redisReply*)redisCommand(conn, Getcomm(Sa, HASH_LEN).c_str());
			if ( reply->str!= NULL)
			{
				Decode(Sv, reply->str, reply->len);
			}			
			h2(tmp1, st2, HASH_LEN);
			strXor(tmp1, Sv, tmp1, HASH_LEN+4);
			strCopy(sDB, tmp1, 4);
			strCopy(st1, tmp1+4, HASH_LEN);
			iDB = char2int(sDB, 4);
			Reset(IH, HASH_LEN);

			d[threadID].iDB = iDB;
			d[threadID].id = threadID;
			d[threadID].st1 = char2str(st1, HASH_LEN);
			d[threadID].st2 = char2str(st2, HASH_LEN);
			d[threadID].pv2 = char2str(Pv2, HASH_LEN);
			if(RN.count(version) > 0)
			{
				RN[version] = iDB;
			}else{
				RN.insert(std::make_pair(version, iDB));//
			}
			
		//	printf("m-thread- %d\n", threadID);
			int ret = pthread_create(&tids[threadID], NULL, SearchCore, (void*)&d[threadID]);
			if (ret != 0)
			{
				printf("pthread_create error: error_code= %d", ret);
			}
			threadID++;
			strV= char2str(st2, HASH_LEN);
			if(SR.count(astLen) > 0)
			{
				SR[astLen] = strV;

			}else{
				SR.insert(std::make_pair(astLen, strV));//
			}
			strCopy(st2, st1, HASH_LEN);
			astLen++;
			version++;
			h(u, st2, HASH_LEN, 0);
			reply = (redisReply*)redisCommand(conn, Getcomm(u, HASH_LEN).c_str());
			if ( reply->str!= NULL)
			{
				Decode(Pv2, reply->str, reply->len);
			}
		}
		for(i = 0; i< version; i++)
		{
			pthread_join(tids[i], NULL);
		}
		
	}
	
	freeReplyObject(reply);	
	redisFree(conn);
	return;

}