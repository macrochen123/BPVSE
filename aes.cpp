#include "aes.h"
/*
*�������������ĳ���
*���룺���ĳ���M_Len,��Ĵ�С���̶����ɼ��ܳ��Ⱦ�����
*���룺���ĳ���
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
*������AES�����㷨
*���룺��ϢM����Կkey,��Ϣ����
*���������cipher�����ĳ��ȡ�
*
*/
S32 AES_E(U8* Cipher,U8 *Message,U8 *Key,S32 M_Len)
{
	/**********************************************************/
	S32 block_m;//��Ϣ����
	S32 padding;
	S32 i,j;
	S32 nk;//��Կ����


	S8 key_temp[MAX_BLOCK_SIZE];//MAX_BLOCK_SIZE= 16 ��ʾ��Ĵ�С
	S8 temp[MAX_BLOCK_SIZE];
	S8 iv[MAX_BLOCK_SIZE];//AES������裬
	S8 buff;
	aes a;


	nk = MAX_BLOCK_SIZE;//������ʼ��
	i = 0;
	j = 0;
	block_m = 0;
	padding = 0;//��¼����������
	for(i = 0;i < MAX_BLOCK_SIZE;i++)
	{
		temp[i] = 0;//��ʼ��temp
		iv[i] = (S8)i;//��ʼ��iv
		key_temp[i] = (S8)Key[i];//��Կ��ֵ
	}
	buff = 0;
	/**********************************************************/
	if (!aes_init(&a,MR_CBC,nk,key_temp,iv))//��ʼ��a
	{
		printf("Failed to Initialize\n");
		return 0;
	}

	block_m = (S32)M_Len/MAX_BLOCK_SIZE;// M_Len / MAX_BLOCK_SIZE

	for(i = 0;i<block_m;i++)//������
	{
		for(j = i*MAX_BLOCK_SIZE; j < (i+1)*MAX_BLOCK_SIZE; j++)//ȡMAX_BLOCK_SIZE���ַ�
		{
			temp[j-i*MAX_BLOCK_SIZE] =(S8)Message[j];
		}
		aes_encrypt(&a,temp);//���ܵ�ǰ��
		for(j = 0; j<MAX_BLOCK_SIZE;j++)//��ֵ����
		{
			Cipher[i*MAX_BLOCK_SIZE+j] = (U8)temp[j];
		}
	}
	return 1;
}


/*
*������AES�����㷨
*���룺����cipher����Կkey�����ĳ���C_len
*���������Message
*���أ�0��1
*/
S32 AES_D(U8* Message,U8* Cipher,U8* Key,S32 C_Len)
{
/**********************************************************/
	S32 block_m;
	S32 i,j;
	S32 nk;//��Կ����

	aes a;

	S8 key_temp[MAX_BLOCK_SIZE];//MAX_BLOCK_SIZE= 16 ��ʾ��Ĵ�С
	S8 temp[MAX_BLOCK_SIZE];
	S8 iv[MAX_BLOCK_SIZE];//AES������裬

	nk = MAX_BLOCK_SIZE;
	for(i = 0;i < MAX_BLOCK_SIZE;i++)
	{
		temp[i] = 0;//��ʼ��temp
		iv[i] = (S8)i;//��ʼ��iv
		key_temp[i] = (S8)Key[i];//��Կ��ֵ
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
