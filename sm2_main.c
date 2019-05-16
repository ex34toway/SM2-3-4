/* https://github.com/karmen27 */
#include<string.h>
#include<iostream.h>
#include<iostd.h>
#include<stdlib.h>

/*********************************
 The recommend curve parameter as below:
	256bit curve
Elliptic curve equation: y^2 = x^3 + a*x + b

p=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
a=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
b=28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
n=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
Gx=32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
Gy=BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
*****************************************/
/*
unsigned int sm2_p[8] = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0, 0xFFFFFFFF, 0xFFFFFFFF};
unsigned int sm2_a[8] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0, 0xFFFFFFFF, 0xFFFFFFFC};
unsigned int sm2_b[8] = {0x28E9FA9E, 0x9D9F5E34, 0x4D5A9E4B, 0xCF6509A7, 0xF39789F5, 0x15AB8F92, 0xDDBCBD41, 0x4D940E93};
unsigned int sm2_n[8] = {0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0x7203DF6B, 0x21C6052B, 0x53BBF409, 0x39D54123};
unsigned int sm2_Gx[8] = {0x32C4AE2C, 0x1F198119, 0x5F990446, 0x6A39C994, 0x8FE30BBF, 0xF2660BE1, 0x715A4589, 0x334C74C7};
unsigned int sm2_Gy[8] = {0xBC3736A2, 0xF4F6779C, 0x59BDCEE3, 0x6B692153, 0xD0A9877C, 0xC62A4740, 0x02DF32E5, 0x2139F0A0};
*/

/* example_1 Fp - 256 */
unsigned char sm2_p[32] = {0x85, 0x42, 0xD6, 0x9E, 0x4C, 0x04, 0x4F, 0x18,
				0xE8, 0xB9, 0x24, 0x35, 0xBF, 0x6F, 0xF7, 0xDE,
				0x45, 0x72, 0x83, 0x91, 0x5C, 0x45, 0x51, 0x7D,
				0x72, 0x2E, 0xDB, 0x8B, 0x08, 0xF1, 0xDF, 0xC3};
unsigned char sm2_a[32] = {0x78, 0x79, 0x68, 0xB4, 0xFA, 0x32, 0xC3, 0xFD, 
				0x24, 0x17, 0x84, 0x2E, 0x73, 0xBB, 0xFE, 0xFF,
				0x2F, 0x3C, 0x84, 0x8B, 0x68, 0x31, 0xD7, 0xE0,
				0xEC, 0x65, 0x22, 0x8B, 0x39, 0x37, 0xE4, 0x98};
unsigned char sm2_b[32] = {0x63, 0xE4, 0xC6, 0xD3, 0xB2, 0x3B, 0x0C, 0x84,
				0x9C, 0xF8, 0x42, 0x41, 0x48, 0x4B, 0xFE, 0x48,
				0xF6, 0x1D, 0x59, 0xA5, 0xB1, 0x6B, 0xA0, 0x6E, 
				0x6E, 0x12, 0xD1, 0xDA, 0x27, 0xC5, 0x24, 0x9A};
unsigned char sm2_Gx[32] = {0x42, 0x1D, 0xEB, 0xD6, 0x1B, 0x62, 0xEA, 0xB6,
				0x74, 0x64, 0x34, 0xEB, 0xC3, 0xCC, 0x31, 0x5E, 
				0x32, 0x22, 0x0B, 0x3B, 0xAD, 0xD5, 0x0B, 0xDC,
				0x4C, 0x4E, 0x6C, 0x14, 0x7F, 0xED, 0xD4, 0x3D};
unsigned char sm2_Gy[32] = {0x06, 0x80, 0x51, 0x2B, 0xCB, 0xB4, 0x2C, 0x07,
				0xD4, 0x73, 0x49, 0xD2, 0x15, 0x3B, 0x70, 0xC4, 
				0xE5, 0xD7, 0xFD, 0xFC, 0xBF, 0xA3, 0x6E, 0xA1,
				0xA8, 0x58, 0x41, 0xB9, 0xE4, 0x6E, 0x09, 0xA2};
unsigned char sm2_n[32] = {0x85, 0x42, 0xD6, 0x9E, 0x4C, 0x04, 0x4F, 0x18, 
				0xE8, 0xB9, 0x24, 0x35, 0xBF, 0x6F, 0xF7, 0xDD,
				0x29, 0x77, 0x20, 0x63, 0x04, 0x85, 0x62, 0x8D,
				0x5A, 0xE7, 0x4E, 0xE7, 0xC3, 0x2E, 0x79, 0xB7};
unsigned char sm2_h[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

unsigned char pub_key[32] = {0x0};
unsigned char priv_key[32] = {0x0};

#if 0
//Step.2 calculate C1=[k]G=(rGx,rGy)

bytes_to_big(SM2_NUMWORD,randK,rand);

ecurve_mult(rand,G,C1); //C1=[k]G

epoint_get(C1,C1x,C1y);

big_to_bytes(SM2_NUMWORD,C1x,C,1);

big_to_bytes(SM2_NUMWORD,C1y,C+SM2_NUMWORD,1);

//Step.3 test if S=[h]pubKey if the point at infinity

ecurve_mult(para_h,pubKey,S);

if (point_at_infinity(S))// if S is point at infinity, return error;
{
	printf("[h]P is infinity.\n");

	return ERR_INFINITY_POINT;
}

//Step.4 calculate [k]PB=(x2,y2)
ecurve_mult(rand,pubKey,kP); //kP=[k]P

epoint_get(kP,x2,y2);

//Step.5 KDF(x2||y2,klen)
big_to_bytes(SM2_NUMWORD,x2,x2y2,1);
big_to_bytes(SM2_NUMWORD,y2,x2y2+SM2_NUMWORD,1);
SM3_KDF(x2y2 ,SM2_NUMWORD*2, klen*8,C+SM2_NUMWORD*2);

if(Test_Null(C+SM2_NUMWORD*3,klen)!=0)
{
	printf("C2 is not on the curve.\n");
	return ERR_ARRAY_NULL;
}

//Step.6 C2=M^t
for (i = 0; i < klen; i++) {
	C[SM2_NUMWORD*2+i]=M[i]^C[SM2_NUMWORD*2+i];
}

//Step.7 C3=hash(x2,M,y2)
SM3_init(&md);
SM3_process(&md,x2y2,SM2_NUMWORD);
SM3_process(&md,M,klen);
SM3_process(&md,x2y2+SM2_NUMWORD,SM2_NUMWORD);
SM3_done(&md,C+SM2_NUMWORD*2+klen);

//Step.2 test if C1 fits the curve
bytes_to_big(SM2_NUMWORD,C,C1x);
bytes_to_big(SM2_NUMWORD,C+SM2_NUMWORD,C1y);
epoint_set(C1x,C1y,0,C1);
i=Test_Point(C1);

if (i != 0) {
	printf("C1 is not on the curve.\n");
	return i;
}

//Step.3 S=[h]C1 and test if S is the point at infinity

ecurve_mult(para_h,C1,S);

if (point_at_infinity(S)) {// if S is point at infinity, return error;
	printf("[h]C1 is infinity.\n");
	return ERR_INFINITY_POINT;
}

//Step.4 [dB]C1=(x2,y2)
ecurve_mult(dB,C1,dBC1);
epoint_get(dBC1,x2,y2);
big_to_bytes(SM2_NUMWORD,x2,x2y2,1);
big_to_bytes(SM2_NUMWORD,y2,x2y2+SM2_NUMWORD,1);

//Step.5 t=KDF(x2||y2,klen)
SM3_KDF(x2y2,SM2_NUMWORD*2,(Clen-SM2_NUMWORD*3),M);

if (Test_Null(M,Clen-SM2_NUMWORD*3) != 0)
	return ERR_ARRAY_NULL;

//Step.6 M=C2^t
for (i = 0; i < Clen-SM2_NUMWORD * 3; i++) {
	M[i] = M[i]^C[SM2_NUMWORD*2+i];
}

//Step.7 hash(x2,m,y2)

SM3_init(&md);

SM3_process(&md,x2y2,SM2_NUMWORD);

SM3_process(&md,M,Clen-SM2_NUMWORD*3);

SM3_process(&md,x2y2+SM2_NUMWORD,SM2_NUMWORD);

SM3_done(&md,hash);

if(memcmp(hash,C-SM2_NUMWORD+Clen,SM2_NUMWORD)!=0) {

	printf("Summary verification error.\n");
	return ERR_C3_MATCH;
} else {
	return 0;
}
#endif

/* generate a 256bit rand between 0 and n */
void generate_rand(void)
{
	rand();
}

void sm2_generate_key_pair(void)
{
	/* generate ramd d ~ (0, n-1) */
	d = generate_rand();
	
	/* P = d G */
	ecurve_mult(d, G, P);

	pub_key = P;
	priv_key = d;
}

void sm2_encrypt(void *pub_key, void *message, void *cipher)
{
	/* generate rand integer */
	generate_rand(rand);

	/* caculate C1=[k]G=(x1,y1) */
	ecurve_mult(rand,G,C1);	

	/* caculate [k]PB=(x2,y2) */
	ecurve_mult(rand,P,c2);

	/* caculate t=KDF(x2.y2, klen) */
	t = KDF_sm3(c2, klen);

	/* caculate C2=M^t */
	C2 = t^message;

	/* caculate C3=Hash(x2 || M || y2) */
	C3 = sha256(c2, message); 

	/* output cipher C = C1 || C2 || C3 */
	cipher = output(C1, C2, C3);

}

void sm2_decrypt(void *priv_key, void *cipher, void *plain_message)
{
	/* check C1 whether satisfy the ECC curve equation */
	Ecc_curve_equation(C1);

	/* check the slope of C1 whether or not equal to infinite */
	infinite_point(C1);

	/* caculate c2 = (x2, y2) = dP */
	ecurve_mult(priv_key, P, c2);

	/* caculate t = KDF(x2.y2, klen) */
	t = KDF_sm3(c2, klen);
	if (t == 0)
		return -1;

	/* caculate M' = C2^t */
	plain_message = t^C2;

	/* caculate hash(x2 || M' || y2) */
	C3' = sha256(c2, plain_message);

	if (C3' == C3)
		return 0;

}
/*
The recommend ECC curve equation is:
y^2 = x^3 + ax + b
*/
int main(int argc, char *argv[])
{
//	unsigned char *pub_key;
//	unsigned char *priv_key;
	unsigned char *message;
	unsigned char *cipher;
	unsigned char *plain_message;

	/* generate sm2 key pairs */
		sm2_generate_key_pair();

	/* encryption test */
		sm2_encrypt(pub_key, message, cipher);

	/* decryption test */
		sm2_decrypt(priv_key, cipher, plain_message);

	return 0;
}



