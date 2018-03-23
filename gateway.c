/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         A very simple Contiki application showing how Contiki programs look
 * \author
 *         Adam Dunkels <adam@sics.se>
 */
#include "contiki.h"
#include "dev/watchdog.h"
#include <stdint.h>
#include <string.h> // CBC mode, for memset
#include "aes.h"

#include <stdio.h>

#include "ecc.h"
#include <ctype.h>
#include <errno.h>

#include "net/rime/rime.h"
#include "random.h"

#include "dev/button-sensor.h"

#include "dev/leds.h"

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define Curve_P_16                                        \
  {                                                       \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF, 0xFD, 0xFF, 0xFF, 0xFF          \
  }
#define Curve_P_24                                                              \
  {                                                                             \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,                       \
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF                                                        \
  }
#define Curve_P_32                                                              \
  {                                                                             \
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,                       \
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF        \
  }
#define Curve_P_48                                                              \
  {                                                                             \
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,                       \
        0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF                                                        \
  }

#define Curve_B_16                                        \
  {                                                       \
    0xD3, 0x5E, 0xEE, 0x2C, 0x3C, 0x99, 0x24, 0xD8, 0x3D, \
        0xF4, 0x79, 0x10, 0xC1, 0x79, 0x75, 0xE8          \
  }
#define Curve_B_24                                                              \
  {                                                                             \
    0xB1, 0xB9, 0x46, 0xC1, 0xEC, 0xDE, 0xB8, 0xFE, 0x49,                       \
        0x30, 0x24, 0x72, 0xAB, 0xE9, 0xA7, 0x0F, 0xE7, 0x80, 0x9C, 0xE5, 0x19, \
        0x05, 0x21, 0x64                                                        \
  }
#define Curve_B_32                                                              \
  {                                                                             \
    0x4B, 0x60, 0xD2, 0x27, 0x3E, 0x3C, 0xCE, 0x3B, 0xF6,                       \
        0xB0, 0x53, 0xCC, 0xB0, 0x06, 0x1D, 0x65, 0xBC, 0x86, 0x98, 0x76, 0x55, \
        0xBD, 0xEB, 0xB3, 0xE7, 0x93, 0x3A, 0xAA, 0xD8, 0x35, 0xC6, 0x5A        \
  }
#define Curve_B_48                                                              \
  {                                                                             \
    0xEF, 0x2A, 0xEC, 0xD3, 0xED, 0xC8, 0x85, 0x2A, 0x9D,                       \
        0xD1, 0x2E, 0x8A, 0x8D, 0x39, 0x56, 0xC6, 0x5A, 0x87, 0x13, 0x50, 0x8F, \
        0x08, 0x14, 0x03, 0x12, 0x41, 0x81, 0xFE, 0x6E, 0x9C, 0x1D, 0x18, 0x19, \
        0x2D, 0xF8, 0xE3, 0x6B, 0x05, 0x8E, 0x98, 0xE4, 0xE7, 0x3E, 0xE2, 0xA7, \
        0x2F, 0x31, 0xB3                                                        \
  }

#define Curve_G_16                                                            \
  {                                                                           \
    {0x86, 0x5B, 0x2C, 0xA5, 0x7C, 0x60, 0x28, 0x0C, 0x2D, 0x9B, 0x89, 0x8B,  \
     0x52, 0xF7, 0x1F, 0x16},                                                 \
    {                                                                         \
      0x83, 0x7A, 0xED, 0xDD, 0x92, 0xA2, 0x2D, 0xC0, 0x13, 0xEB, 0xAF, 0x5B, \
          0x39, 0xC8, 0x5A, 0xCF                                              \
    }                                                                         \
  }

#define Curve_G_24                                                            \
  {                                                                           \
    {0x12, 0x10, 0xFF, 0x82, 0xFD, 0x0A, 0xFF, 0xF4, 0x00, 0x88, 0xA1, 0x43,  \
     0xEB, 0x20, 0xBF, 0x7C, 0xF6, 0x90, 0x30, 0xB0, 0x0E, 0xA8, 0x8D,        \
     0x18},                                                                   \
    {                                                                         \
      0x11, 0x48, 0x79, 0x1E, 0xA1, 0x77, 0xF9, 0x73, 0xD5, 0xCD, 0x24, 0x6B, \
          0xED, 0x11, 0x10, 0x63, 0x78, 0xDA, 0xC8, 0xFF, 0x95, 0x2B, 0x19,   \
          0x07                                                                \
    }                                                                         \
  }

#define Curve_G_32                                                            \
  {                                                                           \
    {0x96, 0xC2, 0x98, 0xD8, 0x45, 0x39, 0xA1, 0xF4, 0xA0, 0x33, 0xEB, 0x2D,  \
     0x81, 0x7D, 0x03, 0x77, 0xF2, 0x40, 0xA4, 0x63, 0xE5, 0xE6, 0xBC,        \
     0xF8, 0x47, 0x42, 0x2C, 0xE1, 0xF2, 0xD1, 0x17, 0x6B},                   \
    {                                                                         \
      0xF5, 0x51, 0xBF, 0x37, 0x68, 0x40, 0xB6, 0xCB, 0xCE, 0x5E, 0x31, 0x6B, \
          0x57, 0x33, 0xCE, 0x2B, 0x16, 0x9E, 0x0F, 0x7C, 0x4A, 0xEB, 0xE7,   \
          0x8E, 0x9B, 0x7F, 0x1A, 0xFE, 0xE2, 0x42, 0xE3, 0x4F                \
    }                                                                         \
  }

#define Curve_G_48                                                            \
  {                                                                           \
    {0xB7, 0x0A, 0x76, 0x72, 0x38, 0x5E, 0x54, 0x3A, 0x6C, 0x29, 0x55, 0xBF,  \
     0x5D, 0xF2, 0x02, 0x55, 0x38, 0x2A, 0x54, 0x82, 0xE0, 0x41, 0xF7,        \
     0x59, 0x98, 0x9B, 0xA7, 0x8B, 0x62, 0x3B, 0x1D, 0x6E, 0x74, 0xAD,        \
     0x20, 0xF3, 0x1E, 0xC7, 0xB1, 0x8E, 0x37, 0x05, 0x8B, 0xBE, 0x22,        \
     0xCA, 0x87, 0xAA},                                                       \
    {                                                                         \
      0x5F, 0x0E, 0xEA, 0x90, 0x7C, 0x1D, 0x43, 0x7A, 0x9D, 0x81, 0x7E, 0x1D, \
          0xCE, 0xB1, 0x60, 0x0A, 0xC0, 0xB8, 0xF0, 0xB5, 0x13, 0x31, 0xDA,   \
          0xE9, 0x7C, 0x14, 0x9A, 0x28, 0xBD, 0x1D, 0xF4, 0xF8, 0x29, 0xDC,   \
          0x92, 0x92, 0xBF, 0x98, 0x9E, 0x5D, 0x6F, 0x2C, 0x26, 0x96, 0x4A,   \
          0xDE, 0x17, 0x36                                                    \
    }                                                                         \
  }

#define Curve_N_16                                        \
  {                                                       \
    0x15, 0xA1, 0x38, 0x90, 0x1B, 0x0D, 0xA3, 0x75, 0x00, \
        0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF          \
  }
#define Curve_N_24                                                              \
  {                                                                             \
    0x31, 0x28, 0xD2, 0xB4, 0xB1, 0xC9, 0x6B, 0x14, 0x36,                       \
        0xF8, 0xDE, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF                                                        \
  }
#define Curve_N_32                                                              \
  {                                                                             \
    0x51, 0x25, 0x63, 0xFC, 0xC2, 0xCA, 0xB9, 0xF3, 0x84,                       \
        0x9E, 0x17, 0xA7, 0xAD, 0xFA, 0xE6, 0xBC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF        \
  }
#define Curve_N_48                                                              \
  {                                                                             \
    0x73, 0x29, 0xC5, 0xCC, 0x6A, 0x19, 0xEC, 0xEC, 0x7A,                       \
        0xA7, 0xB0, 0x48, 0xB2, 0x0D, 0x1A, 0x58, 0xDF, 0x2D, 0x37, 0xF4, 0x81, \
        0x4D, 0x63, 0xC7, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
        0xFF, 0xFF, 0xFF                                                        \
  }

static EccPoint curve_G = CONCAT(Curve_G_, ECC_CURVE);
static uint8_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, ECC_CURVE);

int randfd;

void vli_print(uint8_t *p_vli, unsigned int p_size)
{
  while (p_size)
  {
    printf("%02X ", p_vli[p_size - 1]);
    --p_size;
  }
}

int get_vli(char *buf, char *key, uint8_t vli[NUM_ECC_DIGITS])
{
  int i;
  uint8_t bytes[NUM_ECC_DIGITS];
  char *found = strstr(buf, key);
  if (!found)
  {
    printf("Can't find %s\n", key);
    return -1;
  }
  found += strlen(key);
  if (strlen(found) < 2 * NUM_ECC_DIGITS)
  {
    printf("Error: string too short");
    return -1;
  }

  for (i = 0; i < NUM_ECC_DIGITS; ++i)
  {
    unsigned chr;
    if (!isxdigit(found[2 * i]) || !isxdigit(found[2 * i + 1]))
    {
      printf("Error: '%c%c' is not hex\n", found[2 * i], found[2 * i + 1]);
      return -1;
    }
    sscanf(&found[2 * i], "%02x", &chr);
    bytes[i] = chr;
  }

  ecc_bytes2native(vli, bytes);

  return found + 2 * NUM_ECC_DIGITS - buf;
}

void getRandomBytes(char *p_dest, unsigned p_size)
{
  int i;
  // if(read(randfd, p_dest, p_size) != (int)p_size)
  //{
  //    printf("Failed to get random bytes.\n");
  //}
  for (i = 0; i < p_size; i++)
  {
    p_dest[i] = rand() % 16;
  }
}

//================================================================================================
//
//  #####   #####     #####    ####    #####      ###    ###    ###         ####    ##      ##
//  ##  ##  ##  ##   ##   ##  ##       ##  ##    ## ##   ## #  # ##        ##       ##      ##
//  #####   #####    ##   ##  ##  ###  #####    ##   ##  ##  ##  ##        ##  ###  ##  ##  ##
//  ##      ##  ##   ##   ##  ##   ##  ##  ##   #######  ##      ##        ##   ##  ##  ##  ##
//  ##      ##   ##   #####    ####    ##   ##  ##   ##  ##      ##         ####     ###  ###
//
//================================================================================================

EccPoint l_public;
uint8_t l_private[NUM_ECC_DIGITS];
// example of an hash for the message to broadcast(signing a group message)
uint8_t l_hash[NUM_ECC_DIGITS] = {0};
uint8_t l_random[NUM_ECC_DIGITS];

uint8_t r[NUM_ECC_DIGITS];
uint8_t s[NUM_ECC_DIGITS];

uint8_t l_secret[NUM_ECC_DIGITS];

typedef struct datastruct dstr;
struct datastruct
{
  uint8_t r[NUM_ECC_DIGITS];
  uint8_t s[NUM_ECC_DIGITS];
  EccPoint public;
};

typedef struct spGroupStruct spGroup;
struct spGroupStruct
{
  uint8_t partialSecret[NUM_ECC_DIGITS];
  EccPoint sp;
};

linkaddr_t nodesGroup[100];
uint8_t numNodes;
uint8_t points[100][NUM_ECC_DIGITS];
uint8_t partialSecrets[100][NUM_ECC_DIGITS];
void generateSendSecret();
void sendSecret(int nodeAddr);
void sendSpGroup(int newNodeAddr, spGroup *sp);

int i;
//============================================================================================================
//
//   ####    #####  ##     ##  #####  #####      ###    ######  #####         ####  ##   ####    ##     ##
//  ##       ##     ####   ##  ##     ##  ##    ## ##     ##    ##           ##     ##  ##       ####   ##
//  ##  ###  #####  ##  ## ##  #####  #####    ##   ##    ##    #####         ###   ##  ##  ###  ##  ## ##
//  ##   ##  ##     ##    ###  ##     ##  ##   #######    ##    ##              ##  ##  ##   ##  ##    ###
//   ####    #####  ##     ##  #####  ##   ##  ##   ##    ##    #####        ####   ##   ####    ##     ##
//
//============================================================================================================

int generateSignature(void)
{

  //fflush(stdout);
  getRandomBytes((char *)l_private, NUM_ECC_DIGITS * sizeof(uint8_t));

  ecc_make_key(&l_public, l_private, l_private);

  getRandomBytes((char *)l_random, NUM_ECC_DIGITS * sizeof(uint8_t));

  if (!ecdsa_sign(r, s, l_private, l_random, l_hash))
  {
    printf("ecdsa_sign() failed\n");
  }

  if (!ecc_valid_public_key(&l_public))
  {
    printf("Not a valid public key!\n");
  }

  return 1;
}

void hexArrayToString(char *dest, uint8_t *from, int size)
{
  int i = 0, k = 0;
  for (i = 0; i < size; i = i + 2)
  {
    sprintf(&dest[i], "%02X", from[k]);
    k++;
  }
}

/*---------------------------------------------------------------------------*/
PROCESS(hello_world_process, "Gateway");
AUTOSTART_PROCESSES(&hello_world_process);
/*---------------------------------------------------------------------------*/

static void recv_uc(struct unicast_conn *c, const linkaddr_t *from)
{
  char rstr[1 + (NUM_ECC_DIGITS * 2)] = {0};

#ifdef AES128
  uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  uint8_t out[] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                   0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                   0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                   0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7};
#elif defined(AES192)
  uint8_t key[] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
  uint8_t out[] = {0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
                   0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
                   0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
                   0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd};
#elif defined(AES256)
  uint8_t key[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  uint8_t out[] = {0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                   0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                   0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                   0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b};
#endif
  uint8_t iv[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t in[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
  struct AES_ctx ctx;

  memcpy((points[numNodes]), (uint8_t *)packetbuf_dataptr(), sizeof(l_secret));

  hexArrayToString(rstr, points[numNodes], NUM_ECC_DIGITS * 2);
  printf("unicast message RECEIVED from %d.%d:%s\n", from->u8[0], from->u8[1], rstr);

  AES_init_ctx_iv(&ctx, key, iv);

  AES_ECB_decrypt(&ctx, points[numNodes]);

  hexArrayToString(rstr, points[numNodes], NUM_ECC_DIGITS * 2);
  printf("unicast message RECEIVED from %d.%d:%s\n", from->u8[0], from->u8[1], rstr);

  //save nodes
  memcpy(&(nodesGroup[numNodes]), from, sizeof(from));
  numNodes++;
  //now i can create the shared key!
}

int count1 = 0;
char send_secrets_ready = 0;
static void recv_uc_new_nodes(struct unicast_conn *c, const linkaddr_t *from)
{
  char rstr[1 + (NUM_ECC_DIGITS * 2)] = {0};

  memcpy((points[numNodes]), (uint8_t *)packetbuf_dataptr(), sizeof(l_secret));
  hexArrayToString(rstr, points[numNodes], NUM_ECC_DIGITS * 2);
  printf("unicast message NEW NODE RECEIVED from %d.%d:%s\n", from->u8[0], from->u8[1], rstr);
  //save nodes
  memcpy(&(nodesGroup[numNodes]), from, sizeof(from));
  numNodes++;
  //update group Secret
  generateSendSecret();
  send_secrets_ready = 1;
}

static void sent_uc(struct unicast_conn *c, int status, int num_tx)
{
  const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  if (linkaddr_cmp(dest, &linkaddr_null))
  {
    return;
  }
  printf("unicast message sent to %d.%d: status %d num_tx %d\n",
         dest->u8[0], dest->u8[1], status, num_tx);
}

static void sent_uc_new_nodes(struct unicast_conn *c, int status, int num_tx)
{
  const linkaddr_t *dest = packetbuf_addr(PACKETBUF_ADDR_RECEIVER);
  if (linkaddr_cmp(dest, &linkaddr_null))
  {
    return;
  }
  printf("NEW NODE unicast message sent to %d.%d: status %d num_tx %d \n",
         dest->u8[0], dest->u8[1], status, num_tx);
}

void generateSendSecret()
{
  int k = 0;
  char rstr[1 + (NUM_ECC_DIGITS * 2)] = {0};
  uint8_t ss[NUM_ECC_DIGITS];
  //for each nod create a partial secret
  for (k = 0; k < numNodes; k++)
  {
    hexArrayToString(rstr, points[k], NUM_ECC_DIGITS * 2);
    printf("\npoint %d= %s ", k, rstr);
    memcpy((partialSecrets[k]), (points[k]), sizeof(l_secret));
  }

  for (i = 0; i < numNodes; i++)
  {
    uint8_t tempPoint[NUM_ECC_DIGITS];
    char first = 1;

    for (k = 0; k < numNodes; k++)
    {
      if (k != i)
      {
        if (first)
        {
          memcpy((partialSecrets[i]), (points[k]), sizeof(l_secret));
          first = 0;
        }
        else
        {
          vli_modMult(tempPoint, points[k], partialSecrets[i], curve_n);
          memcpy((partialSecrets[i]), tempPoint, sizeof(l_secret));
        }
      }
    }
    vli_modMult(l_secret, partialSecrets[i], points[i], curve_n);
  }

  uint8_t tempPoint[NUM_ECC_DIGITS];
  uint8_t tempPoint2[NUM_ECC_DIGITS];
  memcpy(tempPoint, points[0], sizeof(l_secret));
  for (i = 1; i < numNodes; i++)
  {
    vli_modMult_fast(tempPoint2, points[i], tempPoint);
    memcpy(tempPoint, tempPoint2, sizeof(l_secret));
  }
  hexArrayToString(rstr, l_secret, NUM_ECC_DIGITS * 2);
  printf("--------> Group secret:::%s\n", rstr);

  ecdh_shared_secret(ss, &curve_G, l_secret, NULL);
  hexArrayToString(rstr, ss, NUM_ECC_DIGITS * 2);
  printf("%d--------> MSK secret %s\n", numNodes, rstr);

  for (k = 0; k < numNodes; k++)
  {
    hexArrayToString(rstr, partialSecrets[k], NUM_ECC_DIGITS * 2);
    //memcpy((points[k]), (partialSecrets[k]), sizeof(l_secret));
    printf("secret:::%s\n", rstr);
  }
}

/*---------------------------------------------------------------------------*/
static const struct broadcast_callbacks broadcast_call;
static struct broadcast_conn broadcast;
static const struct unicast_callbacks unicast_callbacks = {recv_uc, sent_uc};
static const struct unicast_callbacks unicast_callbacks2 = {recv_uc_new_nodes, sent_uc_new_nodes};
static struct unicast_conn uc;
/*---------------------------------------------------------------------------*/

void sendSecret(int nodeAddr)
{
  //packetbuf_copyfrom((void *)(&(points[nodeAddr].x)), sizeof(points[nodeAddr].x));
  //packetbuf_copyfrom((void *)((points[nodeAddr])), sizeof(points[nodeAddr]));
  packetbuf_copyfrom((void *)(partialSecrets[nodeAddr]), sizeof(points[nodeAddr]));

  unicast_send(&uc, &(nodesGroup[nodeAddr]));
}

void sendSpGroup(int newNodeAddr, spGroup *sp)
{
  packetbuf_copyfrom((void *)(sp), sizeof(spGroup));
  unicast_send(&uc, &(nodesGroup[newNodeAddr]));
}

//================================================================================================
//
//  ###    ###    ###    ##  ##     ##        ######  ##   ##  #####    #####    ###    ####
//  ## #  # ##   ## ##   ##  ####   ##          ##    ##   ##  ##  ##   ##      ## ##   ##  ##
//  ##  ##  ##  ##   ##  ##  ##  ## ##          ##    #######  #####    #####  ##   ##  ##  ##
//  ##      ##  #######  ##  ##    ###          ##    ##   ##  ##  ##   ##     #######  ##  ##
//  ##      ##  ##   ##  ##  ##     ##          ##    ##   ##  ##   ##  #####  ##   ##  ####
//
//================================================================================================

int count;
PROCESS_THREAD(hello_world_process, ev, data)
{
  static struct etimer et;

  char rstr[1 + (NUM_ECC_DIGITS * 2)] = {0};
  dstr sig;
  PROCESS_EXITHANDLER(unicast_close(&uc); broadcast_close(&broadcast);)

  PROCESS_BEGIN();
  watchdog_stop();
  clock_init();
  //powertrace_start(CLOCK_SECOND * 2);
  broadcast_open(&broadcast, 129, &broadcast_call);
  unicast_open(&uc, 146, &unicast_callbacks);
  //packetbuf_set_datalen(sizeof(sig));

  generateSignature();

  //wait some seconds before starting the broadcast
  etimer_set(&et, 3 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  printf("Start Broadcast:------------------------------------------------>\n");

  memcpy(sig.r, r, sizeof(r));
  memcpy(sig.s, s, sizeof(s));
  memcpy(&(sig.public), &l_public, sizeof(l_public));

  hexArrayToString(rstr, r, NUM_ECC_DIGITS * 2);
  printf("\nR= %s ", rstr);
  hexArrayToString(rstr, s, NUM_ECC_DIGITS * 2);
  printf("\nS= %s ", rstr);

  packetbuf_copyfrom((void *)(&sig), sizeof(sig));
  broadcast_send(&broadcast);

  printf("\nbroadcast message sent\n");

  //---wait 3 seconds before generating secret key
  etimer_set(&et, 30 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  printf("Generate Send Secret-------------------------------------------->\n");
  generateSendSecret();

  //---wait 1 seconds before sending secret key
  etimer_set(&et, CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  printf("send secret:---------------------------------------------------->\n");
  count = 0;
  while (count < numNodes)
  {
    etimer_set(&et, CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    printf("%d to %d\n", numNodes, nodesGroup[count].u8[0]);

    sendSecret(count);
    count++;
  }

  //---wait 2 seconds before changing callbacks for new nodes
  etimer_set(&et, 15 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  unicast_close(&uc);
  unicast_open(&uc, 146, &unicast_callbacks2);

  memcpy(sig.r, r, sizeof(r));
  memcpy(sig.s, s, sizeof(s));
  memcpy(&(sig.public), &l_public, sizeof(l_public));

  //resend broadcast message for new
  printf("Start Broadcast 2:---------------------------------------------->\n");
  packetbuf_copyfrom((void *)(&sig), sizeof(sig));
  broadcast_send(&broadcast);

  while (1)
  {
    static struct etimer et;
    EccPoint pt2;
    spGroup sp;
    uint8_t tempPoint[NUM_ECC_DIGITS];
    /* packetbuf_copyfrom((void *)(&sig), sizeof(sig));
      broadcast_send(&broadcast); */
    etimer_set(&et, CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    if (send_secrets_ready)
    {
      count1 = 0;
      EccPoint pt;
      for (count1 = 0; count1 < numNodes - 1; count1++)
      {
        printf("NEW NODE %d to %d\n", numNodes, nodesGroup[count1].u8[0]);
        sendSecret(count1);
        etimer_set(&et, CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      }

      EccPoint_mult(&pt, &curve_G, points[0], NULL);
      EccPoint_mult(&pt2, &pt, points[1], NULL);
      hexArrayToString(rstr, pt2.x, NUM_ECC_DIGITS * 2);
      printf("\n%dAAA___>gw %s \n", count1, rstr);
      vli_modMult(tempPoint, points[1], points[0], curve_n);
      EccPoint_mult(&pt2, &curve_G, tempPoint, NULL);
      hexArrayToString(rstr, pt2.x, NUM_ECC_DIGITS * 2);
      printf("\n%dAAA___>gw %s \n", count1, rstr);
      for (count1 = 0; count1 < numNodes; count1++)
      {
        EccPoint curve;
        memcpy(&curve, &curve_G, sizeof(EccPoint));
        EccPoint_mult(&pt, &curve, points[count1], NULL);
        vli_set(sp.partialSecret, partialSecrets[count1]);
        memcpy(&(sp.sp), &pt, sizeof(EccPoint));

        EccPoint_mult(&pt2, &pt, partialSecrets[count1], NULL);

        hexArrayToString(rstr, pt2.x, NUM_ECC_DIGITS * 2);

        printf("\n%d--------___>gw %s \n", count1, rstr);
      }

      sendSpGroup(numNodes - 1, &sp);
      send_secrets_ready = 0;
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
