/* SPECK.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 08/08/2021
 *
 * Implementation of the SPECK block cipher with
 * 128 bits block length and 128/192/256 bits key length.
 *
 * This code follows a specification:
 *		- https://eprint.iacr.org/2013/404.pdf
 *
 * and uses other codebases as references:
 *		- https://github.com/nsacyber/simon-speck-supercop/tree/master/crypto_stream
 *
 */

#include "SPECK.h"
#include "config.h"

#ifdef USE_SPECK


// Rotate Left circular shift 32 bits
static uint64_t ROL_64(uint64_t x, uint32_t n)
{
	return x << n | x >> (64 - n);
}

// Rotate Right circular shift 32 bits
static uint64_t ROR_64(uint64_t x, uint32_t n)
{
	return x >> n | x << (64 - n);
}

static void R(uint64_t* x, uint64_t* y, uint64_t k)
{
	*x = ROR_64(*x, 8);
	*x += *y;
	*x ^= k;
	*y = ROL_64(*y, 3);
	*y ^= *x;
}

static void RI(uint64_t* x, uint64_t* y, uint64_t k)
{
	*y ^= *x;
	*y = ROR_64(*y, 3);
	*x ^= k;
	*x -= *y;
	*x = ROL_64(*x, 8);
}

void SPECK_init(SpeckContext* context, uint64_t* key, uint16_t keyLen)
{
	uint64_t A;
	uint64_t B;
	uint64_t C;
	uint64_t D;
	uint64_t i;

	if (keyLen == 128)
	{
		context->nrSubkeys = 32;

		A = key[1];
		B = key[0];

		for (i = 0; i < 32; i++)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
		}
	}
	else if (keyLen == 192)
	{
		context->nrSubkeys = 33;

		A = key[2];
		B = key[1];
		C = key[0];

		for (i = 0; i < 32; i += 2)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
			context->subkeys[i + 1] = A;
			R(&C, &A, i + 1);
		}
		context->subkeys[32] = A;
	}
	else // 256
	{
		context->nrSubkeys = 34;

		A = key[3];
		B = key[2];
		C = key[1];
		D = key[0];

		for (i = 0; i < 33; i += 3)
		{
			context->subkeys[i] = A;
			R(&B, &A, i);
			context->subkeys[i + 1] = A;
			R(&C, &A, i + 1);
			context->subkeys[i + 2] = A;
			R(&D, &A, i + 2);
		}
		context->subkeys[33] = A;
	}
}

void SPECK_encrypt(SpeckContext* context, uint64_t* block, uint64_t* out)
{
	uint8_t i;
	uint64_t x = block[0];
	uint64_t y = block[1];

	for (i = 0; i < context->nrSubkeys; i++)
	{
		R(&x, &y, context->subkeys[i]);
	}

	out[0] = x;
	out[1] = y;
}

void SPECK_decrypt(SpeckContext* context, uint64_t* block, uint64_t* out)
{
	int i;
	uint64_t x = block[0];
	uint64_t y = block[1];

	for (i = context->nrSubkeys - 1; i >= 0; i--)
	{
		RI(&x, &y, context->subkeys[i]);
	}

	out[0] = x;
	out[1] = y;
}

int crypt_main(uint32_t* text, uint32_t* key)
{
	SpeckContext context;
	int i;

	uint64_t cipherText[2];
	uint64_t expectedCipherText[2];
	uint64_t decryptedText[2];


	uint64_t key_in[4];
	uint64_t text_in[2];
	
	text_in[0] = (text[0] << 32) | text[1];
	text_in[1] = (text[2] << 32) | text[3];

	switch (KEYSIZE)
	{
	case 128 :
		key_in[0] = (key[0] << 32) | key[1];
		key_in[1] = (key[2] << 32) | key[3];
		key_in[2] = 0x0000000000000000;
		key_in[3] = 0x0000000000000000;		
		break;
	case 192 :
		key_in[0] = (key[0] << 32) | key[1];
		key_in[1] = (key[2] << 32) | key[3];
		key_in[2] = (key[4] << 32) | key[5];
		key_in[3] = 0x0000000000000000;
		break;
	case 256 :
		key_in[0] = (key[0] << 32) | key[1];
		key_in[1] = (key[2] << 32) | key[3];
		key_in[2] = (key[4] << 32) | key[5];
		key_in[3] = (key[6] << 32) | key[7];
		break;
	
	default:
		break;
	}

	SPECK_init(&context, key_in, KEYSIZE);

	SPECK_encrypt(&context, text_in, cipherText);
	
	text[0] = (uint32_t)(cipherText[0] >> 32);
	text[1] = (uint32_t)(cipherText[0]);
	text[2] = (uint32_t)(cipherText[1] >> 32);
	text[3] = (uint32_t)(cipherText[1]);
	
	SPECK_decrypt(&context, cipherText, decryptedText);



	
	return 0;

}

#endif
