/* GOST.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 06/06/2021
 *
 */

#pragma once

#include <stdio.h>
#include <stdint.h>
#include "config.h"

#ifdef USE_GOST
uint64_t GOST_encrypt(uint64_t block, uint32_t* key);
uint64_t GOST_decrypt(uint64_t encryptedBlock, uint32_t* key);

int crypt_main(uint32_t* text, uint32_t* key);
#endif