#include <stdio.h>
#include <stdlib.h>
//#include "test_sm2_encrypt_and_decrypt.h"
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

//#include "sm2_cipher_error_codes.h"
//#include "sm2_encrypt_and_decrypt.h"

#define INVALID_NULL_VALUE_INPUT     0x1000
#define INVALID_INPUT_LENGTH         0x1001
#define CREATE_SM2_KEY_PAIR_FAIL     0x1002
#define COMPUTE_SM3_DIGEST_FAIL      0x1003
#define ALLOCATION_MEMORY_FAIL       0x1004
#define COMPUTE_SM2_SIGNATURE_FAIL   0x1005
#define INVALID_SM2_SIGNATURE        0x1006
#define VERIFY_SM2_SIGNATURE_FAIL    0x1007
#define EC_POINT_IS_AT_INFINITY      0x1008
#define COMPUTE_SM2_CIPHERTEXT_FAIL  0x1009
#define COMPUTE_SM2_KDF_FAIL         0x100a
#define INVALID_SM2_CIPHERTEXT       0x100b
#define SM2_DECRYPT_FAIL             0x100c

typedef struct sm2_key_pair_structure {
/* Private key is a octet string of 32-byte length. */
        unsigned char pri_key[32];
/* Public key is a octet string of 65 byte length. It is a
   concatenation of 04 || X || Y. X and Y both are SM2 public
   key coordinates of 32-byte length. */
        unsigned char pub_key[65];
} SM2_KEY_PAIR;

/*********************************************************/
int sm2_create_key_pair(SM2_KEY_PAIR *key_pair)
{
	int error_code;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_d = NULL, *bn_x = NULL, *bn_y = NULL;
	const BIGNUM *bn_order;
	EC_GROUP *group = NULL;
	EC_POINT *ec_pt = NULL;
	unsigned char pub_key_x[32], pub_key_y[32];

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_secure_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_x = BN_CTX_get(ctx);
	bn_y = BN_CTX_get(ctx);
	if ( !(bn_y) )
	{
	        goto clean_up;
	}

	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
	        goto clean_up;
	}
	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}

	error_code = CREATE_SM2_KEY_PAIR_FAIL;
	do
	{
		if ( !(BN_rand_range(bn_d, bn_order)) )
		{
			goto clean_up;
		}	
	} while ( BN_is_zero(bn_d) );

	if ( !(EC_POINT_mul(group, ec_pt, bn_d, NULL, NULL, ctx)) )
	{
		goto clean_up;
	}
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt,
						   bn_x,
						   bn_y,
						   ctx)) )
	{
		goto clean_up;
	}	

	if ( BN_bn2binpad(bn_d,
	                  key_pair->pri_key,
			  sizeof(key_pair->pri_key)) != sizeof(key_pair->pri_key) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_x,
	                  pub_key_x,
			  sizeof(pub_key_x)) != sizeof(pub_key_x) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_y,
	                  pub_key_y,
			  sizeof(pub_key_y)) != sizeof(pub_key_y) )
	{
		goto clean_up;
	}

	key_pair->pub_key[0] = 0x4;
	memcpy((key_pair->pub_key + 1), pub_key_x, sizeof(pub_key_x));
	memcpy((key_pair->pub_key + 1 + sizeof(pub_key_x)), pub_key_y, sizeof(pub_key_y));
	error_code = 0;
	
clean_up:
    if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}

	return error_code;
}


/*********************************************************/
int sm2_encrypt_data_test(const unsigned char *message,
                          const int message_len,
			  const unsigned char *pub_key,
			  unsigned char *c1,
			  unsigned char *c3,
			  unsigned char *c2)
{
	int error_code;
	unsigned char k[32] = {0x59, 0x27, 0x6e, 0x27, 0xd5, 0x06, 0x86, 0x1a,
	                       0x16, 0x68, 0x0f, 0x3a, 0xd9, 0xc0, 0x2d, 0xcc,
	                       0xef, 0x3c, 0xc1, 0xfa, 0x3c, 0xdb, 0xe4, 0xce,
	                       0x6d, 0x54, 0xb8, 0x0d, 0xea, 0xc1, 0xbc, 0x21};
	unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char c1_point[65], x2_y2[64];
	unsigned char *t = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_k = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_order, *bn_cofactor;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *pub_key_pt = NULL, *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int i, flag;

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ctx = BN_CTX_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);	
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(pub_key_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	
	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}	

	error_code = COMPUTE_SM2_CIPHERTEXT_FAIL;
	if ( !(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)) )
	{
		goto clean_up;
	}

	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
		goto clean_up;
	}
	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
		goto clean_up;
	}

	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           pub_key_pt,
						   bn_pub_key_x,
						   bn_pub_key_y,
						   ctx)) )
	{
		goto clean_up;
	}

	/* Compute EC point s = [h]Pubkey, h is the cofactor.
	   If s is at infinity, the function returns and reports an error. */
	if ( !(EC_POINT_mul(group, s_pt, NULL, pub_key_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = EC_POINT_IS_AT_INFINITY;
		goto clean_up;
	}
	md = EVP_sm3();

	do
	{
		if ( !(BN_bin2bn(k, sizeof(k), bn_k)) )
		{
			goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
			continue;
		}
		if ( !(EC_POINT_mul(group, c1_pt, bn_k, NULL, NULL, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_mul(group, ec_pt, NULL, pub_key_pt, bn_k, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           ec_pt,
							   bn_x2,
							   bn_y2,
							   ctx)) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_x2,
		                  x2,
				  sizeof(x2)) != sizeof(x2) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_y2,
		                  y2,
				  sizeof(y2)) != sizeof(y2) )
		{
			goto clean_up;
		}
		memcpy(x2_y2, x2, sizeof(x2));
		memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
		
		if ( !(ECDH_KDF_X9_62(t,
		                      message_len,
				      x2_y2,
				      sizeof(x2_y2),
				      NULL,
				      0,
				      md)) )
		{
			error_code = COMPUTE_SM2_KDF_FAIL;
			goto clean_up;
		}

		/* If each component of t is zero, the random number k 
		   should be re-generated. 
		   A fixed random number k is used in this test function,
		   so this case will not happen.*/
		flag = 1;
		for (i = 0; i < message_len; i++)
		{
			if ( t[i] != 0 )
			{
				flag = 0;
				break;
			}
		}		
	} while (flag);
	
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}

	if ( BN_bn2binpad(bn_c1_x,
	                  c1_x,
			  sizeof(c1_x)) != sizeof(c1_x) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_c1_y,
	                  c1_y,
			  sizeof(c1_y)) != sizeof(c1_y) )
	{
		goto clean_up;
	}
	c1_point[0] = 0x4;
	memcpy((c1_point + 1), c1_x, sizeof(c1_x));
	memcpy((c1_point + 1 + sizeof(c1_x)), c1_y, sizeof(c1_y));
	memcpy(c1, c1_point, sizeof(c1_point));
	
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, message, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, c3, NULL);
	
	for (i = 0; i < message_len; i++)
	{
		c2[i] = message[i] ^ t[i];
	}
	error_code = 0;
	
clean_up:
        if (t)
	{
		free(t);
	}
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (pub_key_pt)
	{
		EC_POINT_free(pub_key_pt);
	}
	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}

	return error_code;
}

/*********************************************************/
int sm2_encrypt(const unsigned char *message,
                const int message_len,
		const unsigned char *pub_key,
		unsigned char *c1,
		unsigned char *c3,
		unsigned char *c2)
{
	int error_code;
	unsigned char pub_key_x[32], pub_key_y[32], c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char c1_point[65], x2_y2[64];
	unsigned char *t = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_k = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_pub_key_x = NULL, *bn_pub_key_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_order, *bn_cofactor;
	EC_GROUP *group = NULL;
	const EC_POINT *generator;
	EC_POINT *pub_key_pt = NULL, *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int i, flag;

	memcpy(pub_key_x, (pub_key + 1), sizeof(pub_key_x));
	memcpy(pub_key_y, (pub_key + 1 + sizeof(pub_key_x)), sizeof(pub_key_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ctx = BN_CTX_new()) )
	{
	        goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_k = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_pub_key_x = BN_CTX_get(ctx);
	bn_pub_key_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);	
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(pub_key_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	
	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}	

	error_code = COMPUTE_SM2_CIPHERTEXT_FAIL;
	if ( !(BN_bin2bn(pub_key_x, sizeof(pub_key_x), bn_pub_key_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(pub_key_y, sizeof(pub_key_y), bn_pub_key_y)) )
	{
		goto clean_up;
	}

	if ( !(bn_order = EC_GROUP_get0_order(group)) )
	{
		goto clean_up;
	}
	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(generator = EC_GROUP_get0_generator(group)) )
	{
		goto clean_up;
	}

	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           pub_key_pt,
						   bn_pub_key_x,
						   bn_pub_key_y,
						   ctx)) )
	{
		goto clean_up;
	}

	/* Compute EC point s = [h]Pubkey, h is the cofactor.
	   If s is at infinity, the function returns and reports an error. */
	if ( !(EC_POINT_mul(group, s_pt, NULL, pub_key_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = EC_POINT_IS_AT_INFINITY;
		goto clean_up;
	}
	md = EVP_sm3();

	do
	{
		if ( !(BN_rand_range(bn_k, bn_order)) )
		{
			goto clean_up;
		}
		if ( BN_is_zero(bn_k) )
		{
			continue;
		}
		if ( !(EC_POINT_mul(group, c1_pt, bn_k, NULL, NULL, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_mul(group, ec_pt, NULL, pub_key_pt, bn_k, ctx)) )
		{
			goto clean_up;
		}
		if ( !(EC_POINT_get_affine_coordinates_GFp(group,
		                                           ec_pt,
							   bn_x2,
							   bn_y2,
							   ctx)) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_x2,
		                  x2,
				  sizeof(x2)) != sizeof(x2) )
		{
			goto clean_up;
		}
		if ( BN_bn2binpad(bn_y2,
		                  y2,
				  sizeof(y2)) != sizeof(y2) )
		{
			goto clean_up;
		}
		memcpy(x2_y2, x2, sizeof(x2));
		memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
		
		if ( !(ECDH_KDF_X9_62(t,
		                      message_len,
				      x2_y2,
				      sizeof(x2_y2),
				      NULL,
				      0,
				      md)) )
		{
			error_code = COMPUTE_SM2_KDF_FAIL;
			goto clean_up;
		}

		/* If each component of t is zero, the random number k 
		   should be re-generated. */
		flag = 1;
		for (i = 0; i < message_len; i++)
		{
			if ( t[i] != 0 )
			{
				flag = 0;
				break;
			}
		}		
	} while (flag);
	
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}

	if ( BN_bn2binpad(bn_c1_x,
	                  c1_x,
			  sizeof(c1_x)) != sizeof(c1_x) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_c1_y,
	                  c1_y,
			  sizeof(c1_y)) != sizeof(c1_y) )
	{
		goto clean_up;
	}
	c1_point[0] = 0x4;
	memcpy((c1_point + 1), c1_x, sizeof(c1_x));
	memcpy((c1_point + 1 + sizeof(c1_x)), c1_y, sizeof(c1_y));
	memcpy(c1, c1_point, sizeof(c1_point));
	
	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, message, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, c3, NULL);
	
	for (i = 0; i < message_len; i++)
	{
		c2[i] = message[i] ^ t[i];
	}
	error_code = 0;
	
clean_up:
        if (t)
	{
		free(t);
	}
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (pub_key_pt)
	{
		EC_POINT_free(pub_key_pt);
	}
	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}

	return error_code;
}

/*********************************************************/
int sm2_decrypt(const unsigned char *c1,
                const unsigned char *c3,
		const unsigned char *c2,
		const int c2_len,
		const unsigned char *pri_key,
		unsigned char *plaintext)
{
	int error_code;
	unsigned char c1_x[32], c1_y[32], x2[32], y2[32];
	unsigned char x2_y2[64], digest[32];
	unsigned char *t = NULL, *M = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *bn_d = NULL, *bn_c1_x = NULL, *bn_c1_y = NULL;
	BIGNUM *bn_x2 = NULL, *bn_y2 = NULL;
	const BIGNUM *bn_cofactor;
	EC_GROUP *group = NULL;
	EC_POINT *c1_pt = NULL, *s_pt = NULL, *ec_pt = NULL;
	const EVP_MD *md;
	EVP_MD_CTX *md_ctx = NULL;
	int message_len, i, flag;

	message_len = c2_len;
	memcpy(c1_x, (c1 + 1), sizeof(c1_x));
	memcpy(c1_y, (c1 + 1 + sizeof(c1_x)), sizeof(c1_y));

	error_code = ALLOCATION_MEMORY_FAIL;
	if ( !(ctx = BN_CTX_new()) )
	{
	   goto clean_up;
	}
	BN_CTX_start(ctx);
	bn_d = BN_CTX_get(ctx);
	bn_c1_x = BN_CTX_get(ctx);
	bn_c1_y = BN_CTX_get(ctx);
	bn_x2 = BN_CTX_get(ctx);
	bn_y2 = BN_CTX_get(ctx);
	if ( !(bn_y2) )
	{
		goto clean_up;
	}
	if ( !(group = EC_GROUP_new_by_curve_name(NID_sm2)) )
	{
		goto clean_up;
	}
	
	if ( !(c1_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(s_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}
	if ( !(ec_pt = EC_POINT_new(group)) )
	{
		goto clean_up;
	}

	if ( !(md_ctx = EVP_MD_CTX_new()) )
	{
		goto clean_up;
	}

	error_code = SM2_DECRYPT_FAIL;
	if ( !(BN_bin2bn(pri_key, 32, bn_d)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(c1_x, sizeof(c1_x), bn_c1_x)) )
	{
		goto clean_up;
	}
	if ( !(BN_bin2bn(c1_y, sizeof(c1_y), bn_c1_y)) )
	{
		goto clean_up;
	}
	
	if ( !(EC_POINT_set_affine_coordinates_GFp(group,
	                                           c1_pt,
						   bn_c1_x,
						   bn_c1_y,
						   ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_on_curve(group, c1_pt, ctx) != 1 )
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}

	if ( !(bn_cofactor = EC_GROUP_get0_cofactor(group)) )
	{
		goto clean_up;
	}
	if ( !(EC_POINT_mul(group, s_pt, NULL, c1_pt, bn_cofactor, ctx)) )
	{
		goto clean_up;
	}
	if ( EC_POINT_is_at_infinity(group, s_pt) )
	{
		error_code = INVALID_SM2_CIPHERTEXT;;
		goto clean_up;
	}

	if ( !(EC_POINT_mul(group, ec_pt, NULL, c1_pt, bn_d, ctx)) )
	{
		goto clean_up;
	}
	if ( !(EC_POINT_get_affine_coordinates_GFp(group,
	                                           ec_pt,
						   bn_x2,
						   bn_y2,
						   ctx)) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_x2,
		          x2,
			  sizeof(x2)) != sizeof(x2) )
	{
		goto clean_up;
	}
	if ( BN_bn2binpad(bn_y2,
		          y2,
			  sizeof(x2)) != sizeof(y2) )
	{
		goto clean_up;
	}
	memcpy(x2_y2, x2, sizeof(x2));
	memcpy((x2_y2 + sizeof(x2)), y2, sizeof(y2));
	md = EVP_sm3();
	
	if ( !(t = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	if ( !(ECDH_KDF_X9_62(t,
	                      message_len,
			      x2_y2,
			      sizeof(x2_y2),
			      NULL,
			      0,
			      md)) )
	{
		error_code = COMPUTE_SM2_KDF_FAIL;
		goto clean_up;
	}

	/* If each component of t is zero, the function 
	   returns and reports an error. */
	flag = 1;
	for (i = 0; i < message_len; i++)
	{
		if ( t[i] != 0 )
		{
			flag = 0;
			break;
		}
	}
	if (flag)
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}
	
	if ( !(M = (unsigned char *)malloc(message_len)) )
	{
		goto clean_up;
	}
	for (i = 0; i < message_len; i++)
	{
		M[i] = c2[i] ^ t[i];
	}

	EVP_DigestInit_ex(md_ctx, md, NULL);
	EVP_DigestUpdate(md_ctx, x2, sizeof(x2));
        EVP_DigestUpdate(md_ctx, M, message_len);
	EVP_DigestUpdate(md_ctx, y2, sizeof(y2));
        EVP_DigestFinal_ex(md_ctx, digest, NULL);
	
	if ( memcmp(digest, c3, sizeof(digest)) )
	{
		error_code = INVALID_SM2_CIPHERTEXT;
		goto clean_up;
	}
	memcpy(plaintext, M, message_len);
	error_code = 0;

clean_up:
        if (ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if (group)
	{
		EC_GROUP_free(group);
	}

	if (c1_pt)
	{
		EC_POINT_free(c1_pt);
	}
	if (s_pt)
	{
		EC_POINT_free(s_pt);
	}
	if (ec_pt)
	{
		EC_POINT_free(ec_pt);
	}
	
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
	}
	
	if (t)
	{
		free(t);
	}
	if (M)
	{
		free(M);
	}

	return error_code;
}

/*********************************************************/
int test_with_input_defined_in_standard(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	unsigned char pub_key[] = {0x04, 0x09, 0xf9, 0xdf, 0x31, 0x1e, 0x54, 0x21, 0xa1,
	                                 0x50, 0xdd, 0x7d, 0x16, 0x1e, 0x4b, 0xc5, 0xc6,
					 0x72, 0x17, 0x9f, 0xad, 0x18, 0x33, 0xfc, 0x07,
					 0x6b, 0xb0, 0x8f, 0xf3, 0x56, 0xf3, 0x50, 0x20,
					 0xcc, 0xea, 0x49, 0x0c, 0xe2, 0x67, 0x75, 0xa5,
					 0x2d, 0xc6, 0xea, 0x71, 0x8c, 0xc1, 0xaa, 0x60,
					 0x0a, 0xed, 0x05, 0xfb, 0xf3, 0x5e, 0x08, 0x4a,
					 0x66, 0x32, 0xf6, 0x07, 0x2d, 0xa9, 0xad, 0x13};
	unsigned char pri_key[32] = {0x39, 0x45, 0x20, 0x8f, 0x7b, 0x21, 0x44, 0xb1,
	                             0x3f, 0x36, 0xe3, 0x8a, 0xc6, 0xd3, 0x9f, 0x95,
	                             0x88, 0x93, 0x93, 0x69, 0x28, 0x60, 0xb5, 0x1a,
	                             0x42, 0xfb, 0x81, 0xef, 0x4d, 0xf7, 0xc5, 0xb8};
	unsigned char std_c1[65] = {0x04, 0x04, 0xeb, 0xfc, 0x71, 0x8e, 0x8d, 0x17, 0x98,
	                                  0x62, 0x04, 0x32, 0x26, 0x8e, 0x77, 0xfe, 0xb6,
					  0x41, 0x5e, 0x2e, 0xde, 0x0e, 0x07, 0x3c, 0x0f,
					  0x4f, 0x64, 0x0e, 0xcd, 0x2e, 0x14, 0x9a, 0x73,
					  0xe8, 0x58, 0xf9, 0xd8, 0x1e, 0x54, 0x30, 0xa5,
					  0x7b, 0x36, 0xda, 0xab, 0x8f, 0x95, 0x0a, 0x3c,
					  0x64, 0xe6, 0xee, 0x6a, 0x63, 0x09, 0x4d, 0x99,
					  0x28, 0x3a, 0xff, 0x76, 0x7e, 0x12, 0x4d, 0xf0};
	unsigned char std_c3[32] = {0x59, 0x98, 0x3c, 0x18, 0xf8, 0x09, 0xe2, 0x62,
	                            0x92, 0x3c, 0x53, 0xae, 0xc2, 0x95, 0xd3, 0x03,
				    0x83, 0xb5, 0x4e, 0x39, 0xd6, 0x09, 0xd1, 0x60,
				    0xaf, 0xcb, 0x19, 0x08, 0xd0, 0xbd, 0x87, 0x66};
	unsigned char std_c2[19] = {0x21, 0x88, 0x6c, 0xa9, 0x89, 0xca, 0x9c, 0x7d,
	                            0x58, 0x08, 0x73, 0x07, 0xca, 0x93, 0x09, 0x2d,
				    0x65, 0x1e, 0xfa};
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext by using input defined in standard failed!\n");
		free(c2);
		return error_code;
	}

	if ( memcmp(c1, std_c1, sizeof(std_c1)) )
	{
		printf("C1 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c3, std_c3, sizeof(std_c3)) )
	{
		printf("C3 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}
	if ( memcmp(c2, std_c2, sizeof(std_c2)) )
	{
		printf("C2 component of SM2 ciphertext is invalid!\n");
		free(c2);
		return (-1);
	}

	printf("Create SM2 ciphertext by using input defined in standard succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(std_c1); i++)
	{
		printf("%02x", c1[i]);
	}
	printf("\n\n");
        printf("C2 component:\n");
        for (i = 0; i < sizeof(std_c2); i++)
        {
                printf("%02x", c2[i]);
        }
        printf("\n\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(std_c3); i++)
	{
		printf("%02x", c3[i]);
	}
	printf("\n\n");

	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext by using private key defined in standard failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("%02x", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("%02x", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext by using private key defined in standard succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}

/*********************************************************/
int test_sm2_encrypt_and_decrypt(void)
{
	int error_code;
	unsigned char msg[] = {"encryption standard"};
	int msg_len = (int)(strlen((char *)msg));
	SM2_KEY_PAIR key_pair;
	unsigned char c1[65], c3[32];
	unsigned char *c2, *plaintext;
	int i;

	if ( error_code = sm2_create_key_pair(&key_pair) )
	{
		printf("Create SM2 key pair failed!\n");
		return (-1);
	}
	printf("Create SM2 key pair succeeded!\n");
	printf("Private key:\n");
	for (i = 0; i < sizeof(key_pair.pri_key); i++)
	{
		printf("0x%x  ", key_pair.pri_key[i]);
	}
	printf("\n\n");
	printf("Public key:\n");
	for (i = 0; i < sizeof(key_pair.pub_key); i++)
	{
		printf("0x%x  ", key_pair.pub_key[i]);
	}
	printf("\n\n");

	printf("/*********************************************************/\n");
	if ( !(c2 = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}
	if ( error_code = sm2_encrypt_data_test(msg,
	                                        msg_len,
						key_pair.pub_key,
						c1,
						c3,
						c2) )
	{
		printf("Create SM2 ciphertext failed!\n");
		free(c2);
		return error_code;
	}

	printf("Create SM2 ciphertext succeeded!\n");
	printf("SM2 ciphertext:\n\n");
	printf("C1 component:\n");
	for (i = 0; i < sizeof(c1); i++)
	{
		printf("%02x", c1[i]);
	}
	printf("\n");
        printf("C2 component:\n");
        for (i = 0; i < msg_len; i++)
        {
                printf("%02x", c2[i]);
        }
        printf("\n");
	printf("C3 component:\n");
	for (i = 0; i < sizeof(c3); i++)
	{
		printf("%02x", c3[i]);
	}
	printf("\n");
	printf("Message: %s\n", msg);
	printf("The length of message is %d bytes.\n", msg_len);
	printf("The length of C2 component is %d bytes.\n", msg_len);

	if ( !(plaintext = (unsigned char *)malloc(msg_len)) )
	{
		printf("Memory allocation failed!\n");
		return ALLOCATION_MEMORY_FAIL;
	}

	if ( error_code = sm2_decrypt(c1,
		                      c3,
				      c2,
				      msg_len,
				      key_pair.pri_key,
				      plaintext) )
	{
		free(plaintext);
		free(c2);
		printf("Decrypt SM2 ciphertext failed!\n");
		return error_code;
	}
	if ( memcmp(plaintext, msg, msg_len) )
	{
		printf("Decrypted plaintext is different from the input message!\n");
		return SM2_DECRYPT_FAIL;
	}
	printf("Input message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("%02x", msg[i]);
	}
	printf("\n");
	printf("Decrypted message:\n");
	for (i = 0; i < msg_len; i++)
	{
		printf("%02x", plaintext[i]);
	}
	printf("\n");
	printf("Decrypt SM2 ciphertext succeeded!\n");

	free(plaintext);
	free(c2);
	return 0;
}

/*********************************************************/
int main(void)
{
        int error_code;

        printf("/*********************************************************/\n");
        if ( error_code = test_with_input_defined_in_standard() )
        {
                printf("Test SM2 encrypt data and decrypt ciphertext with input defined in standard failed!\n");
                return error_code;
        }
        else
        {
                printf("Test SM2 encrypt data and decrypt ciphertext with input defined in standard succeeded!\n");
        }
#if 0
        printf("\n/*********************************************************/\n");
        if ( error_code = test_sm2_encrypt_and_decrypt() )
        {
                printf("Test create SM2 key pair, encrypt data and decrypt ciphertext failed!\n");
                return error_code;
        }
        else
        {
                printf("Test create SM2 key pair, encrypt data and decrypt ciphertext succeeded!\n");
        }
#endif
#if defined(_WIN32) || defined(_WIN64)
  system("pause");
#endif
        return 0;
}

