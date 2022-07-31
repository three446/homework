#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define _CRT_SECURE_NO_WARNINGS
uint8_t input[64] = {
		0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
		0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12,
	};
struct node {
	uint8_t* data;
	node* leftnode;
	node* rightnode;
};
node* top = NULL;
int depth = 0;

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

uint8_t* SM3(uint8_t input[64], uint8_t input1[64])
{
	uint32_t out_len = 0;
	uint8_t sm3_value[EVP_MAX_MD_SIZE];
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_MD_CTX_init(ctx);
	EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(ctx, input, 64);
	EVP_DigestUpdate(ctx, input1, 64);
	EVP_DigestFinal_ex(ctx, sm3_value, &out_len);
	EVP_MD_CTX_reset(ctx);
	return sm3_value;
}

void merkletree(uint8_t* input)
{
	if (top == NULL) {
		node* t1 = (node*)malloc(sizeof(node));
		t1->data = input;
		t1->leftnode = NULL;
		t1->rightnode = NULL;
		top = t1;
		return;
	}
	int depth1 = 0;
	node* nodec = top;
	while (nodec->rightnode != NULL) {
		nodec = nodec->rightnode;
		depth1++;
	}
	if (depth1 == depth) {
		node* newtop = (node*)malloc(sizeof(node));
		newtop->leftnode = top;
		newtop->rightnode = (node*)malloc(sizeof(node));
		newtop->rightnode->data = input;
		newtop->rightnode->leftnode = NULL;
		newtop->rightnode->rightnode = NULL;
		uint8_t* output = SM3(newtop->rightnode->data, newtop->rightnode->data);
		newtop->data = output;
		top = newtop;
		depth++;
	}
	else {
		nodec->leftnode = (node*)malloc(sizeof(node));
		nodec->leftnode->data = nodec->data;
		nodec->leftnode->leftnode = NULL;
		nodec->leftnode->rightnode = NULL;
		nodec->rightnode = (node*)malloc(sizeof(node));
		nodec->rightnode->data = input;
		nodec->rightnode->leftnode = NULL;
		nodec->rightnode->rightnode = NULL;
		uint8_t* output = SM3(nodec->leftnode->data, nodec->rightnode->data);
		nodec->data = output;	
	}
}

int main()
{

	for (int i = 1; i < 100001; i++) {
		merkletree(input);
		if (i % 10000 == 0) {
			printf("第%d个节点正在生成,深度是%d\n", i,depth);
		}
	}
	return 0;
}
