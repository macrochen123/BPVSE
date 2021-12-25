#include "aes.h"
/*
*描述：计算密文长度
*输入：明文长度M_Len,块的大小（固定，由加密长度决定）
*输入：密文长度
*/

S32 AES_Get_C_Len(S32 M_Len,S32 Block_S)
{
/**********************************************************/
	S32 C_Len;
	S32 block_m;
	S32 padding;

	C_Len = 0;
	padding  = 0;
/**********************************************************/
	block_m  = (S32)M_Len/Block_S;
	padding  = M_Len % Block_S;

	if(padding!=0)
	{
		C_Len = (block_m+2)*Block_S;
	}
	else
	{
		C_Len = (block_m+1)*Block_S;
	}

	return C_Len;	
}
/*
*描述：AES加密算法
*输入：消息M，密钥key,消息长度
*输出：密文cipher，密文长度。
*
*/
S32 AES_E(U8* Cipher,U8 *Message,U8 *Key,S32 M_Len)
{
	/**********************************************************/
	S32 block_m;//消息块数
	S32 padding;
	S32 i,j;
	S32 nk;//密钥长度


	S8 key_temp[MAX_BLOCK_SIZE];//MAX_BLOCK_SIZE= 16 表示块的大小
	S8 temp[MAX_BLOCK_SIZE];
	S8 iv[MAX_BLOCK_SIZE];//AES填充所需，
	S8 buff;
	aes a;


	nk = MAX_BLOCK_SIZE;//变量初始化
	i = 0;
	j = 0;
	block_m = 0;
	padding = 0;//记录所需填充个数
	for(i = 0;i < MAX_BLOCK_SIZE;i++)
	{
		temp[i] = 0;//初始化temp
		iv[i] = (S8)i;//初始化iv
		key_temp[i] = (S8)Key[i];//密钥赋值
	}
	buff = 0;
	/**********************************************************/
	if (!aes_init(&a,MR_CBC,nk,key_temp,iv))//初始化a
	{
		printf("Failed to Initialize\n");
		return 0;
	}

	block_m = (S32)M_Len/MAX_BLOCK_SIZE;// M_Len / MAX_BLOCK_SIZE

	for(i = 0;i<block_m;i++)//逐块加密
	{
		for(j = i*MAX_BLOCK_SIZE; j < (i+1)*MAX_BLOCK_SIZE; j++)//取MAX_BLOCK_SIZE个字符
		{
			temp[j-i*MAX_BLOCK_SIZE] =(S8)Message[j];
		}
		aes_encrypt(&a,temp);//加密当前块
		for(j = 0; j<MAX_BLOCK_SIZE;j++)//赋值密文
		{
			Cipher[i*MAX_BLOCK_SIZE+j] = (U8)temp[j];
		}
	}
	return 1;
}


/*
*描述：AES解密算法
*输入：密文cipher，密钥key，密文长度C_len
*输出：明文Message
*返回：0或1
*/
S32 AES_D(U8* Message,U8* Cipher,U8* Key,S32 C_Len)
{
/**********************************************************/
	S32 block_m;
	S32 i,j;
	S32 nk;//密钥长度

	aes a;

	S8 key_temp[MAX_BLOCK_SIZE];//MAX_BLOCK_SIZE= 16 表示块的大小
	S8 temp[MAX_BLOCK_SIZE];
	S8 iv[MAX_BLOCK_SIZE];//AES填充所需，

	nk = MAX_BLOCK_SIZE;
	for(i = 0;i < MAX_BLOCK_SIZE;i++)
	{
		temp[i] = 0;//初始化temp
		iv[i] = (S8)i;//初始化iv
		key_temp[i] = (S8)Key[i];//密钥赋值
	}
/**********************************************************/
	if (!aes_init(&a,MR_CBC,nk,key_temp,iv))
    {
        printf("Failed to Initialize\n");
        return 0;
    }

	block_m = C_Len / MAX_BLOCK_SIZE;
	aes_reset(&a,MR_CBC,iv);

	for(i = 0;i < block_m;i++)
	{
		for(j = i*MAX_BLOCK_SIZE;j<(i+1)*MAX_BLOCK_SIZE;j++)
		{
			temp[j-i*MAX_BLOCK_SIZE]=Cipher[j];
		}
		aes_decrypt(&a,temp);
		for(j = 0;j < MAX_BLOCK_SIZE;j++)
		{
			Message[i*MAX_BLOCK_SIZE+j] = (U8)temp[j];
		}
	}

   aes_end(&a);
   return 1;
}
