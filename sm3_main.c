/** ...: https://github.com/liuqun/openssl-sm4-demo/blob/cmake/src/main.c */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/err.h"
#include "openssl/evp.h"

typedef struct {
	const unsigned char *in_data;
	size_t in_data_len;
	unsigned char *hash;
	unsigned int hash_len;
	int in_data_is_already_padded;
	//const unsigned char *in_ivec;
} test_case_t;

void test_md_with_sm3(test_case_t *in)
{
#if 0
	EVP_CIPHER_CTX *ctx;
	EVP_CIPHER *cipher;	

	cipher = EVP_sm4_ecb();

	EVP_CIPHER_CTX_new();

	EVP_EncryptInit_ex();
	EVP_EncryptUpdate();
	EVP_EncryptFinal_ex();

	EVP_CIPHER_CTX_free();
#endif
	EVP_MD_CTX *md_ctx;
	const EVP_MD *md;
	
	md = EVP_sm3();
	md_ctx = EVP_MD_CTX_new();

	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, in->in_data, in->in_data_len);
	EVP_DigestFinal_ex(md_ctx, in->hash, &in->hash_len);

	EVP_MD_CTX_free(md_ctx);
}

unsigned long get_file_size(unsigned char *file) {
        unsigned long file_size;
        FILE* fp;
        fp = fopen(file, "rb");
        fseek(fp, 0L, SEEK_END);
        file_size = ftell(fp);
        fclose(fp);
        printf("file_size = %ld\n", file_size);

        return file_size;
}

void main(int argc, char *argv[])
{

	test_case_t in_2;
	int i;
#if 0
	unsigned char hash2[32];
	unsigned char data2[] = {'a', 'b', 'c'};
	size_t in_data2_len = strlen((char *)data2);//sizeof(data);
	
	in_2.in_data = data2;
	in_2.in_data_len = in_data2_len;
	in_2.hash = hash2;
	in_2.hash_len = 32;

	test_md_with_sm3(&in_2);

	for (i = 0; i < 32; i++) {
		printf("hash2[%d] = 0x%x\n", i, hash2[i]);
	}
#endif
#if 1   /* test the bin have the convert char such as 0xa*/
        FILE *fp_in;
        unsigned char hash[32];
        unsigned char *data;
        unsigned long data_len;
        test_case_t in;

        if (argv[1] == NULL)
                return;
        fp_in = fopen(argv[1], "rw+");

        data_len = get_file_size(argv[1]);	/* the size includes the convert string */
#if 1
	data_len = 49416;//karmen
#endif
        data = malloc(data_len);
        memset(data, 0, data_len);

        fread(data, data_len, 1, fp_in);
/*
        for (i = data_len - 128; i < data_len; i++) {
                printf("data[%d] = 0x%x\n", i, data[i]);
        }
*/
        in.in_data = data;
        in.in_data_len = data_len;
        in.hash = hash;
        in.hash_len = 32;

        test_md_with_sm3(&in);

        for (i = 0; i < 32; i++) {
                printf("hash[%d] = 0x%x\n", i, hash[i]);
        }

        fclose(fp_in);
        if (data)
                free(data);
#endif

#if 0	/* test the bin have the convert char such as 0xa*/
	FILE *fp_in;
	unsigned char hash[32];
	unsigned char *data;
	unsigned long data_len;
	test_case_t in;
	
	if (argv[1] == NULL)
		return;
	fp_in = fopen(argv[1], "rw+");

	data_len = get_file_size(argv[1]) - 1;
	
	data = malloc(data_len);
	memset(data, 0, data_len);

	fread(data, data_len, 1, fp_in);

        for (i = 0; i < data_len; i++) {
                printf("data[%d] = 0x%x\n", i, data[i]);
        }

	in.in_data = data;
	in.in_data_len = data_len;
	in.hash = hash;
	in.hash_len = 32;

	test_md_with_sm3(&in);

        for (i = 0; i < 32; i++) {
                printf("hash[%d] = 0x%x\n", i, hash[i]);
        }

	fclose(fp_in);
	if (data)
		free(data);
#endif


}






