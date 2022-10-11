/* GOST.c
*
 * Author: Vinicius Borba da Rocha
 * Created: 06/06/2021
 *
 * Implementation of the GOST block cipher with
 * 64 bits block length and 256 bits key length.
 *
 * This code follows a specification:
 *		- https://datatracker.ietf.org/doc/html/rfc5830
 *
 * and uses other codebases as references:
 *		- https://github.com/rbingabo/GOST-block-cipher
 *
 */

#include "GOST.h"
#include "config.h"

#ifdef USE_GOST

uint32_t CM1;
uint32_t CM2;
uint32_t N1;
uint32_t N2;
uint32_t R;

// S-box used by the Central Bank of Russian Federation
const uint8_t s_box[8][16] = {
									{ 4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 },
									{ 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 },
									{ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11 },
									{ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3 },
									{ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2 },
									{ 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14 },
									{ 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12 },
									{ 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }
};

void GOST_round(uint32_t xi)
{
	CM1 = (N1 + xi) % 4294967296; // 2^32

	// read entire s-box column according to the CM1 bits
	uint32_t SN = 0;
	for (int j = 0; j <= 7; j++)
	{
		/*
		* 32 bits input is divided into 8 parts, each of 4 bits
		* to a correponding substitution point column point
		* in the s-box
		*
		* The line below generate a random column that will be
		* read from the s-box at each line and based on the
		* size of the total 16 columns of s-box (and thus % 16)
		*/
		uint8_t Ni = (CM1 >> (4 * (7 - j))) % 16;
		Ni = s_box[j][Ni]; // substitution through s-blocks.

		// place the read bits to correct position in the 32 bit output
		uint32_t mask = 0;
		mask = mask | Ni;
		mask = mask << (28 - (4 * j));
		SN = SN | mask;
	}

	R = SN;

	// cyclic 11 shift
	uint32_t mask = R << 11;
	R = (R >> 21) | mask;

	// modulo 2 addition
	CM2 = R ^ N2;
	N2 = N1;
	N1 = CM2;
}

uint64_t GOST_encrypt(uint64_t block, uint32_t* key)
{
	N1 = (uint32_t)block;
	N2 = block >> 32;

	// first 24 rounds
	for (int k = 0; k < 3; k++)
	{
		for (int i = 0; i <= 7; i++)
		{
			GOST_round(key[i]);
		}
	}

	// last 8 rounds
	for (int i = 7; i >= 0; i--)
	{
		GOST_round(key[i]);
	}

	uint64_t tc = N1;
	tc = (tc << 32) | N2;
	return tc;
}

uint64_t GOST_decrypt(uint64_t encryptedBlock, uint32_t* key)
{
	N1 = (uint32_t)encryptedBlock;
	N2 = encryptedBlock >> 32;

	// last 8 rounds
	for (int i = 0; i <= 7; i++)
	{
		GOST_round(key[i]);
	}

	// first 24 rounds
	for (int k = 0; k < 3; k++)
	{
		for (int i = 7; i >= 0; i--)
		{
			GOST_round(key[i]);
		}
	}

	uint64_t tc = N1;
	tc = (tc << 32) | N2;
	return tc;
}

int crypt_main(uint32_t* text, uint32_t* key){

	uint64_t text_in = (text[0] << 32) | text[1];

	uint64_t cipherText = GOST_encrypt(text_in, key);

	text[0] = (uint32_t)(cipherText >> 32);
	text[1] = (uint32_t)(cipherText);

	uint64_t decrypted = GOST_decrypt(cipherText, key);

	
	return 0;
	
}
#endif