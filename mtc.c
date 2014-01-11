/* -*- C -*- ****************************************************************
 *
 *  System        : crypt-mt
 *  Module        : mtc.c
 *  Created By    : Russ Magee
 *  Created       : Thu Jan 9 16:43:06 2014
 *  Last Modified : <140110.2043>
 *
 *  Description	
 *
 *  An extremely minimal implementation of a cryptMT (-like) stream cipher
 *  using a nonlinear transformation (multiplication) and MSB extraction
 *  from a 32-bit accumulator generated using the Mersenne-Twister PRNG.
 *  
 *  For more information see the paper
 *  "Cryptographic Mersenne Twister and Fubuki Stream/Block Cipher",
 *  by Makoto Matsumoto, Takuji Nishimura, Mariko Hagita and Matsuo Saito
 *  [http://eprint.iacr.org/2005/165.pdf]
 * 
 *
 *  Notes
 * 
 *  This implementation is implemented without any consultation of the
 *  paper's authors, and no endorsement from said authors is implied. No
 *  claim of compatibility with other 'cryptMT' implementations is claimed
 *  nor is any FITNESS FOR A GIVEN PURPOSE claimed or implied by the author
 *  (Russ Magee).
 * 
 *  This program makes use of the Mersenne-Twister library 'mtwist.c',
 *  version 1.4 or newer, written by Geoff Kuenning, and licensed under
 *  the LGPL, available here:
 *  [http://www.cs.hmc.edu/~geoff/mtwist.html]
 *
 ****************************************************************************
 *
 *  Copyright (c) 2014 Russ Magee. Placed under the GPL v3 or newer, see
 *  'gpl.txt' distributed with this source code.
 * 
 *  All Rights Reserved.
 * 
 ****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

#define MT_GENERATE_CODE_IN_HEADER 0

#include "mtwist.h"

static const char rcsid[] = "@(#) : $Id$";

#define MIN(a,b) ((a) <= (b) ? (a) : (b))

typedef char char_t;

typedef struct _exec_context {
    mt_state mts;
    uint32_t accum;
} exec_ctx;

void mtc_init(exec_ctx* ctx)
{
    memset(&ctx->mts, 0, sizeof(mt_state));
}

void mtc_set_key(exec_ctx* ctx, char_t key[])
{
    /* TODO: Use SHA-1 or greater to generate full
     * 624-word state vector for seedfull() */
    /* TODO: bounds enforcement on input data or
     * generated vector */
    uint32_t iv[MT_STATE_SIZE] = {0U};
    uint8_t *ptemp = (uint8_t *)iv;
    uint32_t bytes_to_copy = MT_STATE_SIZE * sizeof(uint32_t);
    
    while( bytes_to_copy > 0 ) {
        if( strlen(key) <= bytes_to_copy ) {
            memcpy(ptemp, (uint32_t*)key, strlen(key));
            bytes_to_copy -= strlen(key);
            ptemp += strlen(key);
        }
        else {
            memcpy(ptemp, (uint32_t*)key, bytes_to_copy);
            bytes_to_copy = 0U;
        }
    }
    
    mts_seedfull(&ctx->mts, iv);
}

void mtc_emit_values(exec_ctx* ctx, uint32_t num)
{
    for(uint32_t index = 0U; index < num; index++) {
        printf("v: %lu\n", mts_lrand(&ctx->mts));
    }
    printf("Done.\n");
}

void mtc_prime_for_crypto(exec_ctx* ctx) {
    ctx->accum = 1U;
    uint32_t prime_rounds = 10000u;
    
    while( --prime_rounds > 0u ) {
        ctx->accum = ctx->accum * (mts_lrand(&ctx->mts) | 1u);
    }
}

uint8_t mtc_encrypt(exec_ctx* ctx, uint8_t pt) {
    uint8_t ct = pt;
#ifndef _BARE_MT_OUTPUT
    /* TODO */
    ct = ((ctx->accum >> 24) & 0xFF) ^ pt;
    ctx->accum = ctx->accum * (mts_lrand(&ctx->mts) | 1u);
#else
    ct = ct ^ ((mts_lrand(&ctx->mts) >> 24) & 0xFF);
#endif
    return ct;
}

uint8_t mtc_decrypt(exec_ctx* ctx, uint8_t ct) {
    /* encrypt and decrypt are identical, invertible ops */
    return mtc_encrypt(ctx, ct);
}

int32_t main(int32_t argc, char_t *argv[])
{
    exec_ctx ctx;
    uint8_t inbyte = 0u;
    int32_t stat = 0;
    
    char_t defkey[] = "This is a default test key. It should be very long... "
          "long enough, in fact, to ensure the entire 624 uint32_t state "
          "vector of Mersenne Twister is non-zero; otherwise apparently the "
          "algorithm collapses to outputting 0 after a small number of "
          "calls to mts_lrand().";
    char_t* key = defkey;
    
#ifdef _BARE_MT_OUTPUT
    fprintf(stderr, "*** WARNING WARNING *** Bare MT PRNG Mode ***\n");
#endif
    mtc_init(&ctx);
    if( argv[1] != NULL ) {
        key = argv[1];
    }
    
    mtc_set_key(&ctx, key);
#if 0
    mtc_emit_values(&ctx, 3200);
#else
    mtc_prime_for_crypto(&ctx);
    
    while( (stat = getc(stdin)) != EOF ) {
        inbyte = (uint8_t)stat;
        putc(mtc_encrypt(&ctx, inbyte), stdout);
    }
#endif
    return 0;
}

