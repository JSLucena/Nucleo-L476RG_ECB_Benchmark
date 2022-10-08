/* HIGHT.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 13/08/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"

#ifdef USE_HIGHT

typedef struct
{
	uint8_t whiteningKeys[8];
	uint8_t subkeys[128];
} HightContext;

void HIGHT_init(HightContext* context, uint8_t* key);
void HIGHT_encrypt(HightContext* context, uint8_t* block, uint8_t* out);
void HIGHT_decrypt(HightContext* context, uint8_t* block, uint8_t* out);

int crypt_main(int key_size, int text[], int key[], int validation[], int size);

#endif