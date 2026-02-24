/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SHAKE256 wrapper for Linux kernel crypto API
 * Used by FALCON post-quantum signature verification
 */

#ifndef FALCON_SHAKE256_KERNEL_H
#define FALCON_SHAKE256_KERNEL_H

#include <crypto/sha3.h>
#include <linux/string.h>

/*
 * SHAKE256 parameters (FIPS 202)
 * Rate: 1088 bits = 136 bytes
 * Capacity: 512 bits = 64 bytes
 */
#define SHAKE256_RATE 136

/*
 * SHAKE256 context for incremental hashing
 * Uses kernel's SHA3 state structure
 */
typedef struct {
	struct sha3_state state;
	unsigned int squeezed;  /* Track output position for squeezing */
} shake256incctx;

/* Forward declaration of keccak permutation (from crypto/sha3_generic.c) */
extern void crypto_sha3_permute(u64 *state);

/* Initialize SHAKE256 context */
static inline void shake256_inc_init(shake256incctx *sc)
{
	memset(&sc->state, 0, sizeof(sc->state));
	sc->state.rsiz = SHAKE256_RATE;
	sc->state.rsizw = SHAKE256_RATE / 8;  /* In 64-bit words */
	sc->squeezed = 0;
}

/* Absorb data into SHAKE256 */
static inline void shake256_inc_absorb(shake256incctx *sc, const uint8_t *in, size_t len)
{
	unsigned int done = 0;

	/* Handle partial block from previous absorb */
	if (sc->state.partial) {
		unsigned int todo = SHAKE256_RATE - sc->state.partial;
		if (len < todo) {
			memcpy(sc->state.buf + sc->state.partial, in, len);
			sc->state.partial += len;
			return;
		}
		memcpy(sc->state.buf + sc->state.partial, in, todo);
		done = todo;
		sc->state.partial = 0;

		/* XOR buffer into state */
		for (unsigned int i = 0; i < SHAKE256_RATE / 8; i++)
			sc->state.st[i] ^= ((u64 *)(sc->state.buf))[i];
		crypto_sha3_permute(sc->state.st);
	}

	/* Process complete blocks */
	while (len - done >= SHAKE256_RATE) {
		for (unsigned int i = 0; i < SHAKE256_RATE / 8; i++)
			sc->state.st[i] ^= ((u64 *)(in + done))[i];
		crypto_sha3_permute(sc->state.st);
		done += SHAKE256_RATE;
	}

	/* Save remaining data */
	if (len > done) {
		memcpy(sc->state.buf, in + done, len - done);
		sc->state.partial = len - done;
	}
}

/* Finalize absorption phase (apply padding and final permutation) */
static inline void shake256_inc_finalize(shake256incctx *sc)
{
	/* SHAKE256 padding: append 0x1F, then 0x00...00, then 0x80 */
	sc->state.buf[sc->state.partial++] = 0x1F;
	memset(sc->state.buf + sc->state.partial, 0,
	       SHAKE256_RATE - sc->state.partial);
	sc->state.buf[SHAKE256_RATE - 1] |= 0x80;

	/* XOR final block into state */
	for (unsigned int i = 0; i < SHAKE256_RATE / 8; i++)
		sc->state.st[i] ^= ((u64 *)(sc->state.buf))[i];
	crypto_sha3_permute(sc->state.st);

	sc->state.partial = 0;
	sc->squeezed = 0;
}

/* Squeeze output from SHAKE256 (extendable output) */
static inline void shake256_inc_squeeze(uint8_t *out, size_t len, shake256incctx *sc)
{
	unsigned int done = 0;

	while (len > 0) {
		unsigned int offset = sc->squeezed % SHAKE256_RATE;

		/* If we've consumed a full block, permute for the next one */
		if (offset == 0 && sc->squeezed > 0)
			crypto_sha3_permute(sc->state.st);

		unsigned int available = SHAKE256_RATE - offset;
		unsigned int todo = (len < available) ? len : available;

		/* Copy from state */
		memcpy(out + done, ((u8 *)sc->state.st) + offset, todo);

		done += todo;
		len -= todo;
		sc->squeezed += todo;
	}
}

/* Release SHAKE256 context (wipe sensitive data) */
static inline void shake256_inc_ctx_release(shake256incctx *sc)
{
	memzero_explicit(&sc->state, sizeof(sc->state));
	sc->squeezed = 0;
}

#endif /* FALCON_SHAKE256_KERNEL_H */
