/* HIGHT.c
*
 * Author: Vinicius Borba da Rocha
 * Created: 13/08/2021
 *
 * Implementation of the HIGHT block cipher with
 * 64 bits block length and 128 bits key length.
 *
 * This code follows a specification:
 *		- https://www.iacr.org/archive/ches2006/04/04.pdf
 *		- https://datatracker.ietf.org/doc/html/draft-kisa-hight-00#section-3.
 *
 * and uses other codebases as references:
 *		- https://github.com/ilwoong/crypto-primitives/tree/master/hight
 *		- https://github.com/ssrini14/Cryptography/blob/master/code/java/HIGHT.java
 *
 */

#include "HIGHT.h"
#include "config.h"

#ifdef USE_HIGHT


#define NR_ROUNDS 32

// Table generated by the ConstantGeneration function
static const uint8_t DELTA[128] = {
	0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41, 0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
	0x56, 0x2b, 0x15, 0x4a, 0x65, 0x72, 0x39, 0x1c, 0x4e, 0x67, 0x73, 0x79, 0x3c, 0x5e, 0x6f, 0x37,
	0x5b, 0x2d, 0x16, 0x0b, 0x05, 0x42, 0x21, 0x50, 0x28, 0x54, 0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d,
	0x3e, 0x5f, 0x2f, 0x17, 0x4b, 0x25, 0x52, 0x29, 0x14, 0x0a, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x76,
	0x3b, 0x1d, 0x0e, 0x47, 0x63, 0x71, 0x78, 0x7c, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x43, 0x61,
	0x70, 0x38, 0x5c, 0x6e, 0x77, 0x7b, 0x3d, 0x1e, 0x4f, 0x27, 0x53, 0x69, 0x34, 0x1a, 0x4d, 0x26,
	0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01, 0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
	0x64, 0x32, 0x19, 0x0c, 0x46, 0x23, 0x51, 0x68, 0x74, 0x3a, 0x5d, 0x2e, 0x57, 0x6b, 0x35, 0x5a,
};

static uint8_t ROL_8(uint8_t x, uint8_t n)
{
	return x << n | x >> (8 - n);
}

/*static uint8_t ROR_8(uint8_t x, uint8_t n)
{
	return x >> n | x << (8 - n);
}

static void constantGeneration()
{
	int i;
	uint8_t d[128];

	d[0] = 0x5a; // 0101101
	for (i = 1; i < 128; i++)
	{
		d[i] = (uint8_t)((((d[i - 1] << 3) ^ (d[i - 1] << 6)) & 0x40) | (ROR_8(d[i - 1], 1) & 0x7f));
	}
}*/

static uint8_t f0(uint8_t x)
{
	return ROL_8(x, 1) ^ ROL_8(x, 2) ^ ROL_8(x, 7);
}

static uint8_t f1(uint8_t x)
{
	return ROL_8(x, 3) ^ ROL_8(x, 4) ^ ROL_8(x, 6);
}

static void HIGHT_round(uint8_t* x,
				  uint8_t subkey0,
				  uint8_t subkey1,
				  uint8_t subkey2,
				  uint8_t subkey3)
{
	uint8_t temp6 = x[6];
	uint8_t temp7 = x[7];

	x[7] = x[6];
	x[6] = x[5] + (f1(x[4]) ^ subkey2);
	x[5] = x[4];
	x[4] = x[3] ^ (f0(x[2]) + subkey1);
	x[3] = x[2];
	x[2] = x[1] + (f1(x[0]) ^ subkey0);
	x[1] = x[0];
	x[0] = temp7 ^ (f0(temp6) + subkey3);
}

static void HIGHT_inverse_round(uint8_t* x,
						  uint8_t subkey0,
						  uint8_t subkey1,
						  uint8_t subkey2,
						  uint8_t subkey3)
{
	uint8_t temp = x[0];

	x[0] = x[1];
	x[1] = x[2] - (f1(x[0]) ^ subkey3);
	x[2] = x[3];
	x[3] = x[4] ^ (f0(x[2]) + subkey2);
	x[4] = x[5];
	x[5] = x[6] - (f1(x[4]) ^ subkey1);
	x[6] = x[7];
	x[7] = temp ^ (f0(x[6]) + subkey0);
}

void HIGHT_init(HightContext* context, uint8_t* key)
{
	int i;
	int j;
	int index;

	// WhiteningKey Generation
	for (i = 0; i < 4; i++)
	{
		context->whiteningKeys[i] = key[i + 12];
	}

	for (i = 4; i < 8; i++)
	{
		context->whiteningKeys[i] = key[i - 4];
	}

	// Subkey Generation
	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			index = (j - i + 8) & 0x7;
			context->subkeys[16 * i + j] = key[index] + DELTA[16 * i + j];
			context->subkeys[16 * i + j + 8] = key[index + 8] + DELTA[16 * i + j + 8];
		}
	}
}

void HIGHT_encrypt(HightContext* context, uint8_t* block, uint8_t* out)
{
	uint8_t r;
	uint8_t subkey = 0;
	uint8_t x[8];

	// Initial Transformation
	x[0] = block[0] + context->whiteningKeys[0];
	x[1] = block[1];
	x[2] = block[2] ^ context->whiteningKeys[1];
	x[3] = block[3];
	x[4] = block[4] + context->whiteningKeys[2];
	x[5] = block[5];
	x[6] = block[6] ^ context->whiteningKeys[3];
	x[7] = block[7];

	// Rounds
	for (r = 0; r < NR_ROUNDS; r++)
	{
		HIGHT_round(x, context->subkeys[subkey], context->subkeys[subkey + 1], context->subkeys[subkey + 2], context->subkeys[subkey + 3]);
		subkey += 4;
	}

	// Final Transformation
	out[0] = x[1] + context->whiteningKeys[4];
	out[1] = x[2];
	out[2] = x[3] ^ context->whiteningKeys[5];
	out[3] = x[4];
	out[4] = x[5] + context->whiteningKeys[6];
	out[5] = x[6];
	out[6] = x[7] ^ context->whiteningKeys[7];
	out[7] = x[0];
}

void HIGHT_decrypt(HightContext* context, uint8_t* block, uint8_t* out)
{
	uint8_t r;
	uint8_t subkey = 127;
	uint8_t x[8];

	// Final Inverse Transformation
	x[7] = block[6] ^ context->whiteningKeys[7];
	x[6] = block[5];
	x[5] = block[4] - context->whiteningKeys[6];
	x[4] = block[3];
	x[3] = block[2] ^ context->whiteningKeys[5];
	x[2] = block[1];
	x[1] = block[0] - context->whiteningKeys[4];
	x[0] = block[7];

	// Rounds
	for (r = 0; r < NR_ROUNDS; r++)
	{
		HIGHT_inverse_round(x, context->subkeys[subkey], context->subkeys[subkey - 1], context->subkeys[subkey - 2], context->subkeys[subkey - 3]);
		subkey -= 4;
	}

	// Initial Inverse Transformation
	out[0] = x[0] - context->whiteningKeys[0];
	out[1] = x[1];
	out[2] = x[2] ^ context->whiteningKeys[1];
	out[3] = x[3];
	out[4] = x[4] - context->whiteningKeys[2];
	out[5] = x[5];
	out[6] = x[6] ^ context->whiteningKeys[3];
	out[7] = x[7];
}

int crypt_main(uint32_t* text, uint32_t* key)
{
	HightContext context;
	int i;
	uint8_t cipherText[8];
	uint8_t expectedCipherText[8];
	uint8_t decryptedText[8];
	uint8_t key_in[16];
	uint8_t text_in[8];

	key_in[0] = key[0] >> 24;
	key_in[1] = key[0] >> 16;
	key_in[2] = key[0] >> 8;
	key_in[3] = key[0];
	key_in[4] = key[1] >> 24;
	key_in[5] = key[1] >> 16;
	key_in[6] = key[1] >> 8;
	key_in[7] = key[1];
	key_in[8] = key[2] >> 24;
	key_in[9] = key[2] >> 16;
	key_in[10] = key[2] >> 8;
	key_in[11] = key[2];
	key_in[12] = key[3] >> 24;
	key_in[13] = key[3] >> 16;
	key_in[14] = key[3] >> 8;
	key_in[15] = key[3];

	text_in[0] = text[0] >> 24;
	text_in[1] = text[0] >> 16;
	text_in[2] = text[0] >> 8;
	text_in[3] = text[0];
	text_in[4] = text[1] >> 24;
	text_in[5] = text[1] >> 16;
	text_in[6] = text[1] >> 8;
	text_in[7] = text[1];

	HIGHT_init(&context, key_in);
	HIGHT_encrypt(&context, text_in, cipherText);
	HIGHT_decrypt(&context, cipherText, decryptedText);

}

#endif