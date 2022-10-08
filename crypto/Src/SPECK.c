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

int crypt_main(int key_size, int text[], int key[], int validation[], int size)
{
	SpeckContext context;
	int i;

	uint64_t cipherText[2];
	uint64_t expectedCipherText[2];
	uint64_t decryptedText[2];

	uint64_t* txt = &text;

	SPECK_init(&context, key, key_size);

	SPECK_encrypt(&context, txt, cipherText);
	SPECK_decrypt(&context, cipherText, decryptedText);


	for (int i = 0; i < 2; i++)
	{
		// verify if decrypt and TextList is the same
		if (!(decryptedText[i] == txt[i]))
			return 1;
	}
	
	return 0;

}

#endif
