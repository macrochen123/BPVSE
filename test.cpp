#include "test.h"
#include "util.h"
#include "aes.h"
#include "bpvse.h"
#include "Zhang.h"
#include "song.h"
#include "he.h"
#include "chen.h"
#include <string>
#include <hiredis/hiredis.h>
#include <iostream>
#include <sys/time.h>
#include <unistd.h>



extern big Curve_N;

extern std::map< int,  string> T1;
extern std::map< string,  string> T2;
extern std::map< int,  string> T3;
extern std::map< string,  string> T4;
extern std::map< string,  string> T5;

extern std::map< int,  string> Hr;

extern std::map< int,  string> Cr;

void htest()
{
    int i;
    char hash[HASH_LEN];
    char message[3] = {(char)0x01, (char)0x02, (char)0x03};

    for ( i = 0; i < 6; i++)
    {
        h(hash, message, 3, i);
        strPrint(hash, HASH_LEN);
    }

}

void Etest()
{
    int clen;
    char Cipher[32];
    char Message[32];
    char message[32] = { (char)0x00};
    char key[32] = { (char)0x70 };

   clen = AES_E((unsigned char* )Cipher, (unsigned char* )message, (unsigned char* )key,  32);
   strPrint((char*)Cipher, 32);
   AES_D((unsigned char* )Message,(unsigned char* ) Cipher, (unsigned char* )key, 32);
   strPrint((char*)Message, 32);
}

void IntCharTest()
{
    int result;
    int i;
    int test;
    char output[4];
    for ( i = 0; i < 500; i++)
    {    
        result = i;
        int2char(output, result);
        strPrint(output, 4);
        test = char2int(output, 4);
        printf("%d\n", test);
    }


}

void StrCharTest()
{
    char sIndex[HASH_LEN]={(char)0x28 };
    char test[HASH_LEN];
    int len;
    string str;
    str = char2str(sIndex, HASH_LEN);
    printf("%s\n", str);
    len = str2char(test, str);
    strPrint(test, len);
    printf("%d\n", len);
}

void SchemeTest()
{
    struct timeval tstart, trend;
    double timer;
    int counter=1;

    Curve_Init();
    epoint *oPK, *uPK, *keyPoint;
    big osk, usk;
    char ckey[HASH_LEN];

    char tmp[HASH_LEN];
    char version[HASH_LEN];//v1, v2,....
    int DB[KEYWORDLEN] = {2, 1};
    char W[WORD_LEN*KEYWORDLEN] = {
   (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
   (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    };//keyword1; keyword2;
    int wl = 2;
    //W1-1, W_2-2
    char sIndex[10*HASH_LEN]={
    (char)0x01,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x02,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x03,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
      (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
     (char)0x04,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
      (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x05,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x06,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
    };
    char trapdoor[HASH_LEN];
    int i;

    char result[10*HASH_LEN];
    int resultLen = 0;
    char ast[HASH_LEN*10];
    int astLen = 0;
    int aRlen[10];

    char Message[10*HASH_LEN];
    int outputlen;
    char aVer[10*HASH_LEN];
    int averLen = 0;

    int um = 0;
    int fm = 0;
    osk = mirvar(0);
    usk = mirvar(0);
    oPK = epoint_init();
    uPK = epoint_init(); 
    keyPoint = epoint_init(); 
    bigrand(Curve_N, osk);
    bigrand(Curve_N, usk);
    KeyGen(oPK, osk);
    KeyGen(uPK, usk);

    GetKey(ckey, uPK, osk);
    printf("the update times = ");
    scanf("%d", &um);
    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &fm);
    printf("\nthe number of keywords = ");
    scanf("%d", &wl);
    DB[0] = fm;
    for ( i = 0; i < um; i++)
    {
        printf("%d-th update\n", i);
        UPdate(version, ckey, i, W, DB, wl, sIndex);
        /* code */
    }
    ////search the keyword w1
    printf("update finish\n");
    GetKey(ckey, oPK, usk);
    Trapdoor(trapdoor, ckey, um, W, WORD_LEN);

    for(i = 0; i < counter; i++)
    {
        gettimeofday(&tstart, NULL);
        Search(resultLen, astLen, trapdoor);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
    printf("The performance of Search of our = %f ms\n", timer/1000);
    printf("resultlen = %d, astLen = %d\n", resultLen, astLen);

    if(Verify(resultLen, astLen))
    {
        printf("success-Verify\n");
    }else{
        printf("error\n");
    }

}

void DBTest()
{
     // 172.20.109.33 -p 9527
    redisContext* conn = redisConnect("127.0.0.1", 6379);
    if(conn->err)
        printf("connection error:%s\n", conn->errstr);

    string content;
    for(int i = 0; i < 10; i ++){
        string setCommand = "set ";
        setCommand.append(std::to_string(i)); //key
        setCommand.append(" ");

        content = "some"; //value
        setCommand.append(content);
        // cout << setCommand << endl;

        redisReply* reply = (redisReply*)redisCommand(conn, setCommand.c_str());
        freeReplyObject(reply);
    }

    for(int i = 0; i < 10; i ++){
        string getCommand = "get ";
        getCommand.append(std::to_string(i));

        redisReply* reply = (redisReply*)redisCommand(conn, getCommand.c_str());
        printf("%s\n", reply->str);
        freeReplyObject(reply);
    }
    redisFree(conn);

}

void T1insert()
{
    struct timeval tstart, trend;
    double timer;
    int counter = 10;
    //
    int i;
    char key1[HASH_LEN]={
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
    char key[HASH_LEN]={
    (char)0x01,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0x01,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };

    char value[HASH_LEN]={
    (char)0x01,  (char)0x11, (char)0xee, (char)0xee, (char)0xee, (char)0xee, (char)0xee, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0x01,  (char)0xee, (char)0xee, (char)0xee, (char)0xee, (char)0xee, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xee
    };
    char value1[HASH_LEN];

    char EK[2*HASH_LEN];
    char EV[2*HASH_LEN];
    char DV[HASH_LEN];
    string strK, strV;

    // // connect the DB
    string content;
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    timer = 0;
    for(i = 0; i < counter; i++)
    {   
        value[0] = i; 
        key[0] = i;
        string setCommand = "set ";
        Encode(EK, key, HASH_LEN);
        setCommand.append(char2str(EK, 2*HASH_LEN)); //key
        setCommand.append(" ");
        Encode(EV, value, HASH_LEN);
        setCommand.append(char2str(EV, 2*HASH_LEN)); //key
        gettimeofday(&tstart, NULL);
        redisReply* reply = (redisReply*)redisCommand(conn,  setCommand.c_str());
        if(NULL == reply)
        {
            printf("write to redis failed ...\n");
        }
        
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
        freeReplyObject(reply);
    }
    printf("get:\n");
    for(i = 0; i < counter; i++)
    {
        key[0] = i;
        string getCommand = "get ";
        Encode(EK, key1, HASH_LEN);
        getCommand.append(char2str(EK, 2*HASH_LEN)); //key
        gettimeofday(&tstart, NULL);
        redisReply*  reply = (redisReply*)redisCommand(conn, getCommand.c_str());
        if(NULL == reply->str)
        {
            printf("get to redis failed ...\n");
        }
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
        Decode(DV, reply->str, reply->len);
        strPrint(DV, HASH_LEN);
        freeReplyObject(reply);
    }
    redisFree(conn);
    
}

void ZSchemeETest()
{
    struct timeval tstart, trend;
    double timer;
    int counter = 1;

    char ks[HASH_LEN];
    char kr[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
    char trapdoor[2*HASH_LEN] = {0};
    char result[10*HASH_LEN];
    char proof[HASH_LEN];
    int len;
    int um  = 0;// the number of indexes of each keyword
    int wm = 0;//the number of keyword
    int i, j;

    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

    ZKeyGen(ks, kr);

    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &um);
    printf("\nthe number of keywords = ");
    scanf("%d", &wm);

	for(i = 0; i < wm; i++)
	{
        //keyword[0] = i;
        randomStr(keyword, WORD_LEN);

        for ( j = 0; j < um; j++)
        {
            //index[0] = j;
            randomStr(index, HASH_LEN);
            ZUpdate(conn, ks, kr, keyword, WORD_LEN, index, HASH_LEN);
        }
	}
    redisFree(conn);

    ZTrapdoor(trapdoor, ks, keyword, WORD_LEN);
    for(i = 0; i < counter; i++)
    {
        gettimeofday(&tstart, NULL);
        ZSearch(len, proof, trapdoor);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
    printf("The performance of Search of Zhang = %f ms\n", timer/1000);


    printf("the number of :%d \n", len);

    ZVerifyE(len, proof, ks, kr, keyword, WORD_LEN); 
}

void randomTest()
{
    int i;
    char st[HASH_LEN];
    for(i = 0; i < 260; i++)
    {
        randomStr(st, HASH_LEN);
        strPrint(st, HASH_LEN);
    }
}

int MSchemeTest()
{
    struct timeval tstart, trend;
    double timer;
    int counter=1;

    Curve_Init();
    epoint *oPK, *uPK, *keyPoint;
    big osk, usk;
    char ckey[HASH_LEN];

    char tmp[HASH_LEN];
    char version[HASH_LEN];//v1, v2,....
    int DB[KEYWORDLEN] = {2, 1};
    char W[WORD_LEN*KEYWORDLEN] = {
   (char)0x00, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
   (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    };//keyword1; keyword2;
    int wl = 1;
    //W1-1, W_2-2
    char sIndex[10*HASH_LEN]={
    (char)0x01,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x02,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x03,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
      (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
     (char)0x04,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
      (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x05,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0x06,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
     (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, 
    };
    char trapdoor[HASH_LEN];
    int i;

    char result[10*HASH_LEN];
    int resultLen = 0;
    char ast[HASH_LEN*10];
    int astLen = 0;
    int aRlen[10];

    char Message[10*HASH_LEN];
    int outputlen;
    char aVer[10*HASH_LEN];
    int averLen = 0;

    int um = 2;
    int fm = 5000;
    osk = mirvar(0);
    usk = mirvar(0);
    oPK = epoint_init();
    uPK = epoint_init(); 
    keyPoint = epoint_init(); 
    bigrand(Curve_N, osk);
    bigrand(Curve_N, usk);
    KeyGen(oPK, osk);
    KeyGen(uPK, usk);

    GetKey(ckey, uPK, osk);
    printf("the update times = ");
    scanf("%d", &um);
    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &fm);
    printf("\nthe number of keywords = ");
    scanf("%d", &wl);
    DB[0] = fm;
    for ( i = 0; i < um; i++)
    {
        printf("%d-th update\n", i);
        UPdate(version, ckey, i, W, DB, wl, sIndex);

        /* code */
    }
    ////search the keyword w1
    printf("update finish\n");
    GetKey(ckey, oPK, usk);
    Trapdoor(trapdoor, ckey, um, W, WORD_LEN);

    for(i = 0; i < counter; i++)
    {
        gettimeofday(&tstart, NULL);
        MultiSearch(resultLen, astLen, trapdoor);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
   
    printf("The performance of Search of our = %f ms\n", timer/1000);
    resultLen = um*fm;
    printf("resultlen = %d, astLen = %d\n", resultLen, astLen);
   
    if(Verify(resultLen, astLen))
    {
        printf("success-Verify\n");
        return 1;
    }else{
        printf("error\n");
        return 0;
    }
}

void SschemeTest()
{
    char ks[HASH_LEN];
  
    char keyword[WORD_LEN] = {
   (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };

    char trapdoor[2*HASH_LEN] = {0};
    char result[10*HASH_LEN];
    char proof[HASH_LEN];
    int count = 0;
    int len;
    int um  = 0;
    int i;

    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 

    SKeyGen(ks);
    
    for ( i = 0; i < 3; i++)
    {
        index[0] = i;
        SUpdate(conn, ks, keyword, WORD_LEN, index, HASH_LEN);
    }
    redisFree(conn);
    STrapdoor(trapdoor, count, ks, keyword, WORD_LEN);
    printf("result= %d:\n", count);
    SSearch(len, trapdoor, count);

}

void STimeTest()
{
    struct timeval tstart, trend;
    double timer = 0;
    int counter = 1;

    char ks[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };

    char trapdoor[2*HASH_LEN] = {0};
    char result[10*HASH_LEN];
    char proof[HASH_LEN];
    int count = 0;
    int len;
    int um  = 0;// the number of indexes of each keyword
    int wm = 0;//the number of keyword
    int i, j;

    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    SKeyGen(ks);

    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &um);
    printf("\nthe number of keywords = ");
    scanf("%d", &wm);

	for(i = 0; i < wm; i++)
	{
        keyword[0] = i;

        for ( j = 0; j < um; j++)
        {
            index[0] = j;
            SUpdate(conn, ks, keyword, WORD_LEN, index, HASH_LEN);
        }
	}
    redisFree(conn);
    STrapdoor(trapdoor, count, ks, keyword, WORD_LEN);
    printf("result= %d:\n", count);
    for(i = 0; i < counter; i++)
    {
        gettimeofday(&tstart, NULL);
        SSearch(len, trapdoor, count);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
   
    printf("The performance of Search of our = %f ms\n", timer/(1000*counter));

}

void HschemeTest()
{
    char ks[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0x00, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
    char trapdoor[HASH_LEN] = {0};
    char st[HASH_LEN] = {0};
    int wm = 10;//the number of keyword
    int um  = 10;// the number of indexes of each keyword
    int crt;
    int len = 0;
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    HKeyGen(ks);
    crt = CLEN;
    HUpdate(conn, ks, crt, keyword, WORD_LEN, wm, um,  index);
    redisFree(conn);

    HTrapdoor(trapdoor, crt, ks, keyword, WORD_LEN);

    HSearch(len, trapdoor, CLEN, crt);
    printf("result= %d:\n", len);
}

void HTimeTest()
{
    struct timeval tstart, trend;
    double timer = 0;
    int counter = 10;

 
    char ks[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0x00, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
    char trapdoor[HASH_LEN] = {0};
    char st[HASH_LEN] = {0};
    int wm = 10;//the number of keyword
    int um  = 100;// the number of indexes of each keyword
    int crt;
    int len = 0;

    int i;

    HKeyGen(ks);
    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &um);
    printf("\nthe number of keywords = ");
    scanf("%d", &wm);
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    HKeyGen(ks);
    crt = CLEN;
    HUpdate(conn, ks, crt, keyword, WORD_LEN, wm, um,  index);
    redisFree(conn);

    HTrapdoor(trapdoor, crt, ks, keyword, WORD_LEN);
    for(i = 0; i < counter; i++)
    {
        Hr.clear();
        len = 0;
        gettimeofday(&tstart, NULL);
        HSearch(len, trapdoor, CLEN, crt);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
   
    printf("The performance of Search of he = %f ms\n", timer/(1000*counter));

    printf("result= %d:\n", len);

}

void CschemeTest()
{
    char ks[HASH_LEN];
    char kk[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0x00, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };
    char kw[HASH_LEN] = {0};
    char ig[HASH_LEN] = {0};


    int wm = 1;//the number of keyword
    int um  = 100;// the number of indexes of each keyword
    int cu = 0;
    int len = 0;
    int i,j;
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    CKeyGen(ks, kk);
    for(i = 0; i < wm; i++)
    {
        keyword[0] = i;
        for ( j = 0; j < um; j++)
        {
            index[0] = j;
            CUpdate(conn, ks, kk, keyword, WORD_LEN, index);
        }
    }
    redisFree(conn);

    CTrapdoor(cu, kw, ig, ks, keyword, WORD_LEN);
    CSearch(len, cu, kw, ig);
    printf("result = %d\n", len);
    CDecrypt(len, kk);
}

void CTimeTest()
{
    struct timeval tstart, trend;
    double timer = 0;
    int counter = 100;

    char ks[HASH_LEN];
    char kk[HASH_LEN];
    char keyword[WORD_LEN] = {
   (char)0x00, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };//keyword1; keyword2;
    char index[HASH_LEN] = {    
    (char)0xFF,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0x11, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff,
    (char)0xff,  (char)0xff, (char)0xff, (char)0xff, (char)0xfe, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff, (char)0xff
    };

    char kw[HASH_LEN] = {0};
    char ig[HASH_LEN] = {0};


    int wm = 1;//the number of keyword
    int um  = 100;// the number of indexes of each keyword
    int cu = 0;
    int len = 0;
    int i,j, k;

  
    redisContext* conn = redisConnect("127.0.0.1", 6379);   // 172.20.109.33 -p 9527
    if(conn->err)
    {
        printf("connection error:%s\n", conn->errstr);
    } 
    CKeyGen(ks, kk);
    printf("\nthe number of indexes of each keyword = ");
    scanf("%d", &um);
    printf("\nthe number of keywords = ");
    scanf("%d", &wm);

    for(i = 0; i < wm; i++)
    {
        keyword[0] = i;
        for ( j = 0; j < um; j++)
        {
            index[0] = j;
            CUpdate(conn, ks, kk, keyword, WORD_LEN, index);
        }
    }
    redisFree(conn);
    CTrapdoor(cu, kw, ig, ks, keyword, WORD_LEN);

    for(i = 0; i < counter; i++)
    {
        Cr.clear();
        len = 0;
        gettimeofday(&tstart, NULL);
        CSearch(len, cu, kw, ig);
        gettimeofday(&trend, NULL);
        timer = timer + 1000000*(trend.tv_sec - tstart.tv_sec) + trend.tv_usec - tstart.tv_usec;
    }
    printf("The performance of Search of chen = %f ms\n", timer/(1000*counter));
    printf("result= %d:\n", len);
    CDecrypt(len, kk);

}