#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/err.h"
#include "openssl/evp.h"

static const EVP_CIPHER *(*EVP_sm4_ecb)()=EVP_aes_128_ecb;

#define TEST_SM4 1

typedef struct {
    const unsigned char *in_data;
    size_t in_data_len;
    int in_data_is_already_padded;
    const unsigned char *in_ivec;
    const unsigned char *in_key;
    size_t in_key_len;
} test_case_t;

void test_encrypt_with_cipher(const test_case_t *in, const EVP_CIPHER *cipher, unsigned char *out)
{
    unsigned char *out_buf = NULL;
    int out_len;
    int out_padding_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, in->in_key, in->in_ivec);

    if (in->in_data_is_already_padded)
    {
        /* Check whether the input data is already padded.
        And its length must be an integral multiple of the cipher's block size. */
        const size_t bs = EVP_CIPHER_block_size(cipher);
        if (in->in_data_len % bs != 0)
        {
            printf("ERROR-1: data length=%d which is not added yet; block size=%d\n", (int) in->in_data_len, (int) bs);
            /* Warning: Remember to do some clean-ups */
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
        /* Disable the implicit PKCS#7 padding defined in EVP_CIPHER */
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    out_buf = (unsigned char *) malloc(((in->in_data_len>>4)+1) << 4);
    out_len = 0;

	EVP_EncryptUpdate(ctx, out_buf, &out_len, in->in_data, in->in_data_len);

    if (0)
    {
        printf("Debug: out_len=%d\n", out_len);
    }

    out_padding_len = 0;
    EVP_EncryptFinal_ex(ctx, out_buf+out_len, &out_padding_len);
    if (0)
    {
        printf("Debug: out_padding_len=%d\n", out_padding_len);
    }

    EVP_CIPHER_CTX_free(ctx);
    if (1)
    {
        int i;
        int len;
        len = out_len + out_padding_len;

	memcpy(out, out_buf, len);
        for (i=0; i<len; i++)
        {
           // printf("%02x-%02x ", out_buf[i], out[i]);
        }
    }

    if (out_buf)
    {
        free(out_buf);
        out_buf = NULL;
    }
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

int main(int argc, char* argv[])
{

	unsigned char data_tmp[16];
	unsigned char *data_tmp_out;
	unsigned char *data_in;
	unsigned char *data_out;
	int i = 0, padding;
	unsigned long file_size;
	FILE *fp_in;
	FILE *fp_out;
	unsigned char ivec[EVP_MAX_IV_LENGTH]; ///< IV ..
    const unsigned char key1[16] = ///< key_data, ...., ..16..
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    test_case_t tc;

	printf("argc = %d, argv[0] = %s, argv[1] = %s\n", argc, argv[0], argv[1]);
	
	if (argv[1] == NULL) {
		printf("please enter src_file , such as:\n ./sm4 file_in.txt file_out.txt\n");
		return 0;
	}

	file_size = get_file_size(argv[1]);
	fp_in = fopen(argv[1], "rb");
	fp_out = fopen(argv[2], "wb");

	padding = file_size % 16;
	printf("padding = %d, file_size = %ld\n", padding, file_size);

        data_in = malloc(file_size + padding);
	memset(data_in, 0, file_size + padding);
        if (data_in == NULL)
                printf("data_in malloc failed\n");

	data_out = malloc(file_size + padding);
	memset(data_out, 0, file_size + padding);
        if (data_out == NULL)
                printf("data_out malloc failed\n");

	fread(data_in, file_size, 1, fp_in);

    tc.in_data_is_already_padded = 1;// Hard coded 16 as the cipher's block size
    tc.in_key = key1;
    tc.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc.in_ivec = ivec;
	
        printf("Debug: EVP_sm4_ecb() test\n");

	for (i = 0; i * 16 < file_size + padding; i++) {
		tc.in_data = data_in + i * 16;
		tc.in_data_len = 16;
		data_tmp_out = data_out + i * 16;
        test_encrypt_with_cipher(&tc, EVP_sm4_ecb(), data_tmp);

		memcpy(data_tmp_out, data_tmp, 16);
		data_tmp_out = data_out + i * 16;
	}

	fwrite(data_out, file_size + padding, 1, fp_out);

	fclose(fp_in);
	fclose(fp_out);
	if (data_in)
		free(data_in);
	if (data_out)
		free(data_out);

	return 0;
}

