/* PRESENT.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 24/07/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"


#ifdef USE_PRESENT

typedef struct
{
	uint64_t roundKeys[32];
} PresentContext;

void PRESENT_init(PresentContext* context, uint16_t* key, uint16_t keyLen);
void PRESENT_encrypt(PresentContext* context, uint16_t* block, uint16_t* out);
void PRESENT_decrypt(PresentContext* context, uint16_t* block, uint16_t* out);

int crypt_main(uint32_t* text, uint32_t* key);

#endif