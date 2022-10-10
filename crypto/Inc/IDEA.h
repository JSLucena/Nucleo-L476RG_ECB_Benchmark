/* IDEA.h
*
 * Author: Vinicius Borba da Rocha
 * Created: 11/07/2021
 *
 */

#pragma once

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "config.h"

#ifdef USE_IDEA

typedef struct
{
	uint16_t encryptionKeys[52];
	uint16_t decryptionKeys[52];
} IdeaContext;

void IDEA_init(IdeaContext* context, uint16_t* key);
void IDEA_encrypt(IdeaContext* context, uint16_t* block, uint16_t* out);
void IDEA_decrypt(IdeaContext* context, uint16_t* encryptedBlock, uint16_t* out);

int crypt_main(uint32_t* text, uint32_t* key);

#endif