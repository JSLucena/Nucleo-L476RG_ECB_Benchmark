/* PRESENT.c
*
 * Author: Vinicius Borba da Rocha
 * Created: 24/07/2021
 *
 * Implementation of the PRESENT block cipher with
 * 64 bits block length and 80/128 bits key length.
 *
 * This code follows a specification:
 *		- https://www.iacr.org/archive/ches2007/47270450/47270450.pdf
 *
 * and uses other codebases as references:
 *		- https://github.com/kurtfu/present
 *		- https://www.oryx-embedded.com/doc/present_8c_source.html
 *		- https://github.com/Pepton21/present-cipher
 *
 */

#include "PRESENT.h"
#include "config.h"

#ifdef USE_PRESENT

#define NR_ROUNDS 31

// s-box
const uint8_t sbox[16] =
{
	0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2
};

// inverse s-box
const uint8_t isbox[16] =
{
	0x5, 0xe, 0xf, 0x8, 0xc, 0x1, 0x2, 0xd, 0xb, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xa
};

// permutation table
const uint8_t p[64] =
{
	0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
	4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
	8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
	12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

void PRESENT_init(PresentContext* context, uint16_t* key, uint16_t keyLen)
{
	uint64_t keyHigh;
	uint64_t keyLow;

	if (keyLen == 80) // generate subkeys for 80 bit key
	{
		keyHigh = key[0];
		keyLow = (uint64_t)key[1] << 48
			| (uint64_t)key[2] << 32
			| (uint64_t)key[3] << 16
			| key[4];

		// first subkey is 64 leftmost bits of the key
		context->roundKeys[0] = keyHigh << 48 | keyLow >> 16;

		for (uint8_t i = 1; i <= NR_ROUNDS; i++)
		{
			//  key register is rotated by 61 bit positions to the left (cyclic left shift of 61)
			uint64_t temp = keyHigh;
			keyHigh = keyLow >> 3 & 0xffff;
			keyLow = keyLow << 61 | temp << 45 | keyLow >> 19;

			// the left-most four bits are passed through the sbox
			temp = sbox[(keyHigh >> 12) & 0xf];
			keyHigh = (keyHigh & 0x0fff) | (temp << 12);

			// round_counter value i is exclusive - ored with bits k19 k18 k17 k16 k15
			keyLow ^= (uint64_t)i << 15;

			// save subkey with 64 leftmost bits of the key
			context->roundKeys[i] = keyHigh << 48 | keyLow >> 16;
		}
	}
	else // generate subkeys assuming key is 128 bits
	{
		keyHigh = (uint64_t)key[0] << 48
			| (uint64_t)key[1] << 32
			| (uint64_t)key[2] << 16
			| key[3];
		keyLow = (uint64_t)key[4] << 48
			| (uint64_t)key[5] << 32
			| (uint64_t)key[6] << 16
			| key[7];

		// first subkey is 64 leftmost bits of the key
		context->roundKeys[0] = keyHigh;

		for (int i = 1; i <= NR_ROUNDS; i++)
		{
			//  key register is rotated by 61 bit positions to the left (cyclic left shift of 61)
			uint64_t temp = keyHigh;
			keyHigh = temp << 61 | keyLow >> 3;
			keyLow = keyLow << 61 | temp >> 3;;

			// the left-most eight bits are passed through the sbox
			temp = sbox[(keyHigh >> 60) & 0xf];
			keyHigh |= temp << 60;
			temp = sbox[(keyHigh >> 56) & 0xf];
			keyHigh |= temp << 56;

			// round_counter value i is exclusive - ored with bits k66 k65 k64 k63 k62
			keyHigh ^= i >> 2;
			keyLow ^= (uint64_t)i << 62;

			// save subkey with 64 leftmost bits of the key
			context->roundKeys[i] = keyHigh;
		}
	}
}

/*
	Encryption order:

	for round = 0 to 30 do
		addRoundKey(state, Ki)
		sBoxLayer(state)
		pLayer(state)
	end for

	addRoundKey(state, k31)
*/
void PRESENT_encrypt(PresentContext* context, uint16_t* block, uint16_t* out)
{
	uint8_t i;
	uint8_t round;
	uint64_t state;
	uint64_t temp;

	// copy block to state
	state = (uint64_t)block[0] << 48
		| (uint64_t)block[1] << 32
		| (uint64_t)block[2] << 16
		| block[3];

	for (round = 0; round < NR_ROUNDS; round++)
	{
		// add round key
		state ^= context->roundKeys[round];

		// sbox substitution layer
		// divide state into 16 parts of 4 bits and substitute these parts
		// according to the sbox
		// in this case we are dividing in 8 parts in the loop, but inside the loop
		// splitting into high and low parts
		temp = 0;
		for (i = 0; i < 8; i++)
		{
			uint8_t pos = (uint8_t)(state >> (8 * (7 - i)));
			uint8_t highNybble = sbox[(pos >> 4) & 0x0f];
			uint8_t lowNybble = sbox[pos & 0x0f];

			uint64_t mask = 0;
			mask |= highNybble << 4 | lowNybble;
			mask = mask << (56 - (8 * i));
			temp |= mask;
		}
		state = temp;

		// permutation layer
		// change order of all bits according to the permutation table
		temp = 0;
		for (i = 0; i < 64; i++)
		{
			uint8_t distance = 63 - i;
			temp |= ((state >> distance & 0x1) << (63 - p[i]));
		}
		state = temp;
	}

	// add last round key
	state ^= context->roundKeys[round];

	// copy state to output;
	out[0] = (uint16_t)(state >> 48);
	out[1] = (uint16_t)(state >> 32);
	out[2] = (uint16_t)(state >> 16);
	out[3] = (uint16_t)state;
}

/*
	Decryption order:

	for round = 31 to 1 do
		addRoundKey(state, Ki)
		inversePLayer(state)
		inverseSBoxLayer(state)
	end for

	addRoundKey(state, k0)
*/
void PRESENT_decrypt(PresentContext* context, uint16_t* block, uint16_t* out)
{
	uint8_t i;
	uint8_t round;
	uint64_t state;
	uint64_t temp;

	// copy block to state
	state = (uint64_t)block[0] << 48
		| (uint64_t)block[1] << 32
		| (uint64_t)block[2] << 16
		| block[3];

	// decrypt we run from last round key to the first one
	for (round = NR_ROUNDS; round > 0; round--)
	{
		// add round key
		state ^= context->roundKeys[round];

		// permutation layer
		// change order of all bits according to the permutation table
		// but in reverse order
		temp = 0;
		for (i = 0; i < 64; i++)
		{
			uint8_t distance = 63 - p[i];
			temp = (temp << 1) | ((state >> distance) & 0x1);
		}
		state = temp;

		// sbox substitution layer
		// divide state into 16 parts of 4 bits and substitute these parts
		// according to the inverse sbox
		// in this case we are dividing in 8 parts in the loop, but inside the loop
		// splitting into high and low parts
		temp = 0;
		for (i = 0; i < 8; i++)
		{
			uint8_t pos = (uint8_t)(state >> (8 * (7 - i)));
			uint8_t highNybble = isbox[(pos >> 4) & 0x0f];
			uint8_t lowNybble = isbox[pos & 0x0f];

			uint64_t mask = 0;
			mask |= highNybble << 4 | lowNybble;
			mask = mask << (56 - (8 * i));
			temp |= mask;
		}
		state = temp;
	}

	// add last key
	state ^= context->roundKeys[round];

	// copy state to output;
	out[0] = (uint16_t)(state >> 48);
	out[1] = (uint16_t)(state >> 32);
	out[2] = (uint16_t)(state >> 16);
	out[3] = (uint16_t)state;
}

int crypt_main(uint32_t* text, uint32_t* key)
{
	PresentContext context;
	int i;
	uint16_t cipherText[4];
	uint16_t expectedCipherText[4];
	uint16_t decryptedText[4];

	uint16_t key_in[8];
	uint16_t text_in[4];
	text_in[0] = text[0] >> 16;
	text_in[1] = text[0];
	text_in[2] = text[1] >> 16;
	text_in[3] = text[1];

	key_in[0] = key[0] >> 16;
	key_in[1] = key[0];
	key_in[2] = key[1] >> 16;
	key_in[3] = key[1];
	key_in[4] = key[2] >> 16;
	key_in[5] = key[2];
	key_in[6] = key[3] >> 16;
	key_in[7] = key[3];


	PRESENT_init(&context, key_in, KEYSIZE);

	PRESENT_encrypt(&context, text_in, cipherText);
	PRESENT_decrypt(&context, cipherText, decryptedText);

	return 0;
}

#endif
