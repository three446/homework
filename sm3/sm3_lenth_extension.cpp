#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define _CRT_SECURE_NO_WARNINGS

uint8_t input_A[64] = {
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, };
uint8_t input_B[64] = {
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, };
uint8_t input_AB[128] = {
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, };

static void dump_buf(uint8_t* buf, uint32_t len)
{
	int i;
	printf("buf:");
	for (i = 0; i < len; i++) {
		printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ",
			buf[i],
			i == len - 1 ? "\r\n" : "");
	}
}

uint8_t* sm3(uint8_t* input, int size)//使用OpenSSL来进行SM3的运算
{
	uint8_t* value;
	uint32_t len = 0;
	value = (uint8_t*)malloc(32);
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, input, size);
	EVP_DigestFinal_ex(ctx, value, &len);
	EVP_MD_CTX_reset(ctx);
	return value;
}

uint8_t* lenth_extension(uint8_t* hash, uint8_t* extensionmessage)//对长度进行扩展
{
	uint8_t input[96];
	for (int i = 0; i < 32; i++) {
		input[i] = hash[i];
	}
	for (int i = 0; i < 64; i++) {
		input[i + 32] = extensionmessage[i];
	}
	uint8_t* output = sm3(input, 96);
	return output;
}

int main()
{
	uint8_t* sm3_value = sm3(input_A, 64);
	uint8_t* res = lenth_extension(sm3_value, input_B);
	printf("A消息的hash：");
	dump_buf((uint8_t*)res, 32);
	uint8_t* org = sm3(input_AB, 128);
	printf("A扩展B后的hash：");
	dump_buf((uint8_t*)org, 32);
	uint8_t* org2 = sm3(input_AB, 128);
	printf("A+B的hash：");
	dump_buf((uint8_t*)org2, 32);
	return 0;
}
