/* -*- C -*- ****************************************************************
 *
 *  System        : crypt-mt
 *  Module        : mtc.c
 *  Created By    : Russ Magee
 *  Created       : Thu Jan 9 16:43:06 2014
 *  Last Modified : <140125.1942>
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
 *  version 1.5 or newer, written by Geoff Kuenning, and licensed under
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
#include "sha2.h"

static const char rcsid[] = "@(#) : $Id$";

#define MIN(a,b) ((a) <= (b) ? (a) : (b))

typedef char char_t;

typedef struct _exec_context {
    uint32_t opts;
    mt_state mts;
    uint32_t accum;
} exec_ctx;

void mtc_init(exec_ctx* ctx)
{
    memset(&ctx->mts, 0, sizeof(mt_state));
}


uint8_t* mtc_sha512_digest(const uint8_t * data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
    SHA512_CTX context;
    
    SHA512_Init(&context);
    SHA512_Update(&context, data, len);
    SHA512_Final(digest, &context);
    return digest;
}

void mtc_set_key(exec_ctx* ctx, char_t key[])
{
    uint32_t iv[MT_STATE_SIZE] = {0U};
    uint8_t *ptemp = (uint8_t *)iv;
    uint32_t bytes_to_copy = MT_STATE_SIZE * sizeof(uint32_t);
    /* Key supplied is likely less than the size of MT state
     * ( 624*sizeof(int32_t) ); so we expand the key material
     * to fill the entire Mersenne Twister state buffer.
     * This is done by repeatedly generating and storing a
     * sha512 hash of: first the key,
     * then each previous partial MT state contents, until
     * the state buffer is filled:
     * 
     * MT_state := Hn
     * where H1 = sha512(key),
     *       H2 = sha512(H1 || H2), H(n>2) = sha512(H1 || .. Hn-1)
     */
    uint8_t hashdata[SHA512_DIGEST_LENGTH] = {0u};
    memcpy(ptemp, mtc_sha512_digest(key, strlen(key), hashdata),
           sizeof(hashdata));
    bytes_to_copy -= strlen(key);
    ptemp += strlen(key);
    while( bytes_to_copy > 0 ) {
        if( sizeof(hashdata) <= bytes_to_copy ) {
            memcpy(ptemp, mtc_sha512_digest((uint8_t*)iv, ptemp-(uint8_t*)iv, hashdata),
                   sizeof(hashdata));
            bytes_to_copy -= sizeof(hashdata);
            ptemp += sizeof(hashdata);
        }
        else {
            memcpy(ptemp, mtc_sha512_digest((uint8_t*)iv, ptemp-(uint8_t*)iv, hashdata),
                   bytes_to_copy);
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

