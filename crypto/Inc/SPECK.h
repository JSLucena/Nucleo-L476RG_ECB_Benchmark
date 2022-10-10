/* SPECK.h
* 
 * Author: Vinicius Borba da Rocha
 * Created: 08/08/2021
 * 
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"


#ifdef USE_SPECK

typedef struct
{
	uint8_t nrSubkeys;
	uint64_t subkeys[34];
} SpeckContext;

void SPECK_init(SpeckContext* context, uint64_t* key, uint16_t keyLen);
void SPECK_encrypt(SpeckContext* context, uint64_t* block, uint64_t* out);
void SPECK_decrypt(SpeckContext* context, uint64_t* block, uint64_t* out);

int crypt_main(uint32_t* text, uint32_t* key);

#endif
