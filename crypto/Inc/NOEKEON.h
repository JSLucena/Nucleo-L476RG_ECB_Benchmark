/* NOEKEON.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 27/07/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"

#ifdef USE_NOEKEON

void NOEKEON_encrypt(uint32_t* block, uint32_t* key, uint32_t* encryptdBlock);
void NOEKEON_decrypt(uint32_t* encryptedBlock, uint32_t* key, uint32_t* decryptedBlock);

int crypt_main(uint32_t* text, uint32_t* key);


#endif