#ifndef PQCLEAN_FALCON_API_H
#define PQCLEAN_FALCON_API_H

/* Kernel headers instead of libc */
#include <linux/types.h>

/* FALCON-512 parameters */
#define FALCON512_CRYPTO_PUBLICKEYBYTES   897
#define FALCON512_CRYPTO_BYTES            752
#define FALCON512_PADDED_CRYPTO_BYTES     666
#define FALCON512_LOGN                    9

/* FALCON-1024 parameters */
#define FALCON1024_CRYPTO_PUBLICKEYBYTES  1793
#define FALCON1024_CRYPTO_BYTES           1462
#define FALCON1024_PADDED_CRYPTO_BYTES    1280
#define FALCON1024_LOGN                   10

/* Legacy aliases (FALCON-512) */
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES   1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES   FALCON512_CRYPTO_PUBLICKEYBYTES
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES            FALCON512_CRYPTO_BYTES
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_ALGNAME          "Falcon-512"
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES      FALCON512_PADDED_CRYPTO_BYTES

/*
 * Verify a signature (sig, siglen) on a message (m, mlen) with a given
 * public key (pk). The logn parameter selects the parameter set:
 *   logn=9  for FALCON-512  (pk is 897 bytes)
 *   logn=10 for FALCON-1024 (pk is 1793 bytes)
 *
 * Return value: 0 on success, -1 on error.
 */
int falcon_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk,
    unsigned logn);

/* Legacy FALCON-512 wrappers */
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk);

int PQCLEAN_FALCON512_CLEAN_crypto_sign_open(
    uint8_t *m, size_t *mlen,
    const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif
