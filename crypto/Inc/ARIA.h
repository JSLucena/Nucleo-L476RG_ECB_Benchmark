/* ARIA.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 20/06/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"

#ifdef USE_ARIA
typedef struct
{
	uint32_t rounds;
	// each subkey is 4 parts of 32 bits
	uint32_t eks[17][4];
	uint32_t dks[17][4];
} AriaContext;

void ARIA_init(AriaContext* context, const uint32_t* key, uint32_t keyLength);
void ARIA_encrypt(AriaContext* context, uint32_t* block, uint32_t* P);
void ARIA_decrypt(AriaContext* context, uint32_t* block, uint32_t* P);

int crypt_main(uint32_t* text, uint32_t* key);

#endif
