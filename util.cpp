#include "util.h"

void gh(char *hash, char *message, int mlen)
{
    int i;
    sha256 sh;
    shs256_init(&sh);
    for (i=0; i < mlen ;i++)
    {
        shs256_process(&sh, message[i]);
    }
    shs256_hash(&sh, hash);
}

void h(char *hash, char *message, int mlen, int flag)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    shs256_process(&sh, flag);
    for (i=0; i < mlen ;i++)
    {
        shs256_process(&sh, message[i]);
    }
    shs256_hash(&sh, hash);
}
//output len = 32+4
void h2(char *hash, char *message, int mlen)
{
    int i, j;
    sha256 sh;
    char K[HASH_LEN];
    shs256_init(&sh);
    shs256_process(&sh, 1);
    for (j = 0; j < mlen; j++)
    {
         shs256_process(&sh, message[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash, K, HASH_LEN);

    shs256_init(&sh);
    shs256_process(&sh, 2);
    for (j = 0; j < mlen; j++)
    {
         shs256_process(&sh, message[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash + HASH_LEN, K, 4);


}

void h34(char *hash, char *message, int mlen, int index, int flag)
{
    int i;
    sha256 sh;
    char cI[4] = {0};
    
    shs256_init(&sh);
    shs256_process(&sh, flag);
    int2char(cI, index);
    for(i = 0; i < 4; i++)
    {
        shs256_process(&sh, cI[i]);
    }
    
    for (i=0; i < mlen ;i++)
    {
        shs256_process(&sh, message[i]);
    }
    shs256_hash(&sh, hash);
}
void addHash(char *newhash, char *oldhash, char *message, int mlen)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    for (i=0; i < HASH_LEN ;i++)
    {
        shs256_process(&sh, oldhash[i]);
    }
    for (i=0; i < mlen ;i++)
    {
        shs256_process(&sh, message[i]);
    }
    shs256_hash(&sh, newhash);
}
///long messsage hash, H(R)
void LMHash(char *hash, char *message, int mlen)
{
    int i;
    int block = mlen/HASH_LEN;
    char IH[HASH_LEN] = {0};
    for ( i = 0; i < block; i++)
    {
        addHash(IH, IH, message+i*HASH_LEN, HASH_LEN);
    }
    strCopy(hash, IH, HASH_LEN);
    
}

void Reset(char *source, int mlen)
{
    int i;
    for ( i = 0; i < mlen; i++)
    {
        source[i] = 0;
        /* code */
    }
    
}

void F1(char *hash, char *keyword, int keywordlen, char *version, char *key, int flag)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    shs256_process(&sh, flag);
    for (i=0; i < keywordlen ;i++)
    {
        shs256_process(&sh, keyword[i]);
    }
    for (i=0; i < KEY_LEN ;i++)
    {
        shs256_process(&sh, version[i]);
        shs256_process(&sh, key[i]);
    }
    shs256_hash(&sh, hash);
}

void hkey(char *hash, char *hd, char *pv, int len, char *st, int stlen)
{
    int i;
    sha256 sh;

    shs256_init(&sh);
    for (i=0; i < len; i++)
    {
        shs256_process(&sh, hd[i]);
        shs256_process(&sh, pv[i]);
    }
    for (i=0; i < stlen ;i++)
    {
        shs256_process(&sh, st[i]);
    }
    shs256_hash(&sh, hash);
}


//////////////////////////////////////////////////////////
void strPrint(char *source, int slen)
{
    int i;

    for (i = 0; i < slen; i++)
    {
        printf("%02X", (unsigned char)source[i]);
    }

    printf("\n");
}
void randomStr(char *output, int len)
{
    int i;
    for ( i = 0; i < len; i++)
    {
        output[i] = (char)rand();
        /* code */
    }
    
}
void strCopy(char *output, char *source, int len)
{
    int i;
    for ( i = 0; i < len; i++)
    {
        output[i] = source[i];
        /* code */
    }
    
}
bool strequal(char *sourceA, char *sourceB, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        if (sourceA[i]!=sourceB[i])
        {
            return false;
            /* code */
        }
        /* code */
    }
    return true;
    
}
void strXor(char * output, char *sourceA, char *sourceB, int len)
{
    int i;
    for ( i = 0; i < len; i++)
    {
        output[i] = sourceA[i] ^ sourceB[i];
        /* code */
    }
    
}
void int2char(char *output, int input)
{
    output[0] = (char) ((unsigned int)input>>24) ;
    output[1] = (char) ((unsigned int)input>>16) ;
    output[2] = (char) ((unsigned int)input>>8) ;
    output[3] = (char) ((unsigned int)input) ;
}

int char2int(char *source, int mlen)
{
    unsigned int result;
    result = ((unsigned int)((unsigned char)source[0])<<24)|((unsigned int)((unsigned char)source[1])<<16)|((unsigned int)((unsigned char)source[2])<<8)|((unsigned int)((unsigned char)source[3]));
    return result;
}
string char2str(char *source, int clen)
{
    string str("");
    for (int i = 0; i < clen; i++)
    {
        str = str + source[i];
        /* code */
    }
    return str;
}
int str2char(char *output, string str)
{
    int len;
    len = str.length();
    str.copy(output, len, 0); 
    return len;
}

//
void PointPrint(epoint *PK)
{
    big x,y;
    char tmp[HASH_LEN];
    x = mirvar(0);
	y = mirvar(0);
	epoint_get(PK, x, y);
	big_to_bytes(HASH_LEN, x, tmp, TRUE);
    strPrint(tmp, HASH_LEN);
	big_to_bytes(HASH_LEN, y, tmp, TRUE);
    strPrint(tmp, HASH_LEN);
	mirkill(x); mirkill(y);
}
void StrPrint(string str)
{
    char tmp[HASH_LEN*2];
    str2char(tmp, str);
    strPrint(tmp, str.length());
    
}

///////////////hom hash function/////////////////////////////
void Hash(char *hash, char *IV, char *M, int mLen)
{
    char hr[HASH_SIZE];
    sha256 sh;
    int i;

	shs256_init(&sh);
   // SM3_Alg_Update(&md, 0x00, 1);
    shs256_process(&sh, 0);
    for ( i = 0; i < HASH_SIZE; i++)
    {
        shs256_process(&sh, IV[i]);
        /* code */
    }
    shs256_hash(&sh, hr);
	
    shs256_init(&sh);
    for ( i = 0; i < mLen; i++)
    {
        shs256_process(&sh, M[i]);
        /* code */
    }
    shs256_hash(&sh, hash);     

    for ( i = 0; i < HASH_SIZE; i++)
    {
        hash[i] = hash[i]^hr[i];
    }
}
//h(a||b)
//h(a||b)
void MulHash(char *hash, char *IV, char *asource, char *bsource)
{
    char hr[HASH_SIZE];
    char mM[2*HASH_SIZE];
    sha256 sh;
    int i,j;

    strCopy(mM, asource, HASH_SIZE);
    strCopy(mM + HASH_SIZE, bsource, HASH_SIZE);

	shs256_init(&sh);
    for ( i = 0; i < HASH_SIZE; i++)
    {
        shs256_process(&sh, IV[i]);
        /* code */
    }
    shs256_hash(&sh, hr);

    strCopy(hash, hr, HASH_SIZE);

    for ( i = 0; i < 2; i++)
    {
        shs256_init(&sh);
        for (j = 0; j < HASH_SIZE; j++)
        {
            shs256_process(&sh, mM[i*HASH_SIZE+j]);
        }
        shs256_hash(&sh, hr);
        for (j = 0; j < HASH_SIZE; j++)
        {
            hash[j] = hash[j]^hr[j];
        }
    }
}
//h
//h(a+b) = h(a)+h(b)
void HomHash(char *hash, char *IV, char *hasha, char *hashb)
{
    char hr[HASH_SIZE];
    sha256 sh;
    int i;

	shs256_init(&sh);
    for ( i = 0; i < HASH_SIZE; i++)
    {
        shs256_process(&sh, IV[i]);
        /* code */
    }
	shs256_hash(&sh, hr);
	

    for ( i = 0; i < HASH_SIZE; i++)
    {
        hash[i] = hr[i]^hasha[i]^hashb[i];
    }
}

void ZF1(char* hash, char *ks, char *keyword, int keywordlen)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    for (i=0; i < HASH_LEN ;i++)
    {
        shs256_process(&sh, ks[i]);
    }
    for (i=0; i < keywordlen ;i++)
    {
        shs256_process(&sh, keyword[i]);
    }
    shs256_hash(&sh, hash);
}
void ZF2(char* hash, char *kr, char *keyword, int keywordlen)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    shs256_process(&sh, 0x02);
    for (i=0; i < HASH_LEN ;i++)
    {
        shs256_process(&sh, kr[i]);
    }
    for (i=0; i < keywordlen ;i++)
    {
        shs256_process(&sh, keyword[i]);
    }
    shs256_hash(&sh, hash);
}

void ZH1(char *hash , char *tw, char *st1, int len)
{
    int j;
    sha256 sh;
    shs256_init(&sh);
    for (j = 0; j < len; j++)
    {
         shs256_process(&sh, tw[j]);
         shs256_process(&sh, st1[j]);
    }
    shs256_hash(&sh, hash);

}


void ZH2(char *hash , char *tw, char *st1, int len)
{
    int j;
    sha256 sh;
    char K[HASH_LEN];
    shs256_init(&sh);
    shs256_process(&sh, 1);
    for (j = 0; j < len; j++)
    {
         shs256_process(&sh, tw[j]);
         shs256_process(&sh, st1[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash, K, HASH_LEN);

    shs256_init(&sh);
    shs256_process(&sh, 2);
    for (j = 0; j < HASH_LEN; j++)
    {
        shs256_process(&sh, K[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash + HASH_LEN, K, HASH_LEN);

}

/// the length of input is HASH_LEN
void Encode(char *output, char *input, int len)
{
  int i = 0;
  unsigned char high;
  unsigned char low;
  for(i = 0; i < len; i ++){
    high =  (input[i] & 0xF0) >> 4;
    low = input[i] & 0x0F;
    output[2*i] = high + OFFSET;
    output[2*i + 1] = low + OFFSET;
    }
}
// the length of input is 2*HASH_LEN
void Decode(char *output, char *input, int len)
{
    unsigned char high, low;
    unsigned char full;
    int i;
    for (i = 0; i < len/2; i ++){
        high = ((input[2*i]) - OFFSET) << 4;
        low = (input[2*i + 1] - OFFSET);
        full = high | low;
        output[i] = full;
    }
}
//the max length of set is 4*HASH_LEN
string Setcomm(char *inputK, int klen, char *inputV, int vlen)
{
    char EK[10*HASH_LEN];
    char EV[10*HASH_LEN];
    string setCommand = "set ";
	Encode(EK, inputK, klen);
	setCommand.append(char2str(EK, 2*klen)); //key
	setCommand.append(" ");
	Encode(EV, inputV, vlen);
    setCommand.append(char2str(EV, 2*vlen)); //key
    return setCommand;
}

string Getcomm(char *inputK, int klen)
{
    char EK[10*HASH_LEN];
    string getCommand = "get ";
    Encode(EK, inputK, klen);
    getCommand.append(char2str(EK, 2*klen)); //key
    return getCommand;
}

string SetcommInt(int inputK, char *inputV, int vlen)
{
    char EV[10*HASH_LEN];
    string setCommand = "set ";
	setCommand.append(std::to_string(inputK)); //key
	setCommand.append(" ");
	Encode(EV, inputV, vlen);
    setCommand.append(char2str(EV, 2*vlen)); //key
    return setCommand;
}
string GetcommInt(int inputK)
{
    string getCommand = "get ";
    getCommand.append(std::to_string(inputK)); //key
    return getCommand;
}

//////////////////////
void SF(char *hash, char *key, int klen, char *hw, int hlen)
{
    int i;
    sha256 sh;
    
    shs256_init(&sh);
    for (i=0; i < klen ;i++)
    {
        shs256_process(&sh, key[i]);
    }
    for (i=0; i < hlen ;i++)
    {
        shs256_process(&sh, hw[i]);
    }
    shs256_hash(&sh, hash);
}

void SH1(char *hash, char *tw, char *st, int len)
{
    int j;
    sha256 sh;
    shs256_init(&sh);
    for (j = 0; j < len; j++)
    {
         shs256_process(&sh, tw[j]);
         shs256_process(&sh, st[j]);
    }
    shs256_hash(&sh, hash);
}

void SH2(char *hash, char *tw, char *st, int len)
{
    int i,j;
    char tmp[HASH_LEN];
    sha256 sh;

    for ( i = 0; i < 2; i++)
    {
        shs256_init(&sh);
        shs256_process(&sh, i);
        for (j = 0; j < len; j++)
        {
            shs256_process(&sh, tw[j]);
            shs256_process(&sh, st[j]);
        }
        shs256_hash(&sh, tmp);
        strCopy(hash + i*HASH_LEN, tmp, HASH_LEN);
        
    }
}

void HH(char *hash, char *st, int len)
{
    int j;
    sha256 sh;
    char K[HASH_LEN];
    shs256_init(&sh);
    shs256_process(&sh, 1);
    for (j = 0; j < len; j++)
    {
         shs256_process(&sh, st[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash, K, HASH_LEN);

    shs256_init(&sh);
    shs256_process(&sh, 2);
    for (j = 0; j < HASH_LEN; j++)
    {
        shs256_process(&sh, st[j]);
    }
    shs256_hash(&sh, K);
    strCopy(hash + HASH_LEN, K, HASH_LEN);
}

void HF(char *hash, char *k, int klen, char *keyword, int keywordlen)
{
  
    int i;
    sha256 sh;
    shs256_init(&sh);
    for (i=0; i < klen ;i++)
    {
        shs256_process(&sh, k[i]);
    }
    for (i=0; i < keywordlen ;i++)
    {
        shs256_process(&sh, keyword[i]);
    }
    shs256_hash(&sh, hash);

}
void HHF(char *hash, char *kt, int len, int crt)
{
    int i,j;
    char tmp[HASH_LEN];
    sha256 sh;
  
    strCopy(tmp, kt, HASH_LEN);

    for ( i = 0; i < crt; i++)
    {
        shs256_init(&sh);

        for (j=0; j < HASH_LEN ;j++)
        {
            shs256_process(&sh, tmp[j]);
        }
        shs256_hash(&sh, tmp);
    }
    strCopy(hash, tmp, HASH_LEN);
    
}

void HHI(char *newhash, char *oldhash)
{
    int i;
    char tmp[HASH_LEN];
    sha256 sh;
    shs256_init(&sh);
    for (i=0; i < HASH_LEN ;i++)
    {
        shs256_process(&sh, oldhash[i]);
    }
    shs256_hash(&sh, tmp);
    strCopy(newhash, tmp, HASH_LEN);
    
}

void CF(char *hash, char *ks, char *keyword, int keywordlen, int flag)
{
    int i;
    char tmp[HASH_LEN];
    sha256 sh;
    shs256_init(&sh);
    for (i=0; i < HASH_LEN ;i++)
    {
        shs256_process(&sh, ks[i]);
    }

    for (i=0; i < keywordlen ;i++)
    {
        shs256_process(&sh, keyword[i]);
    }
    shs256_process(&sh, flag);
    shs256_hash(&sh, hash);
}

void CH(char *hash, char *kw, int cu)
{
    int i,j;
    char tmp[HASH_LEN];
    sha256 sh;

    for ( i = 0; i < 2; i++)
    {
        shs256_init(&sh);
        shs256_process(&sh, cu);
        shs256_process(&sh, i);
        for (j = 0; j < HASH_LEN; j++)
        {
            shs256_process(&sh, kw[j]);
        }
        shs256_hash(&sh, tmp);
        strCopy(hash + i*HASH_LEN, tmp, HASH_LEN);
        
    }
}

void CGI(char *hash, char *kw1, char *index, int indexlen)
{
    int j;
    sha256 sh;
    shs256_init(&sh);
    for (j = 0; j < HASH_LEN; j++)
    {
        shs256_process(&sh, kw1[j]);
    }
    for (j = 0; j < indexlen; j++)
    {
        shs256_process(&sh, index[j]);
    }
    shs256_hash(&sh, hash);

}