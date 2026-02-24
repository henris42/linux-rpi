// SPDX-License-Identifier: GPL-2.0
/*
 * FALCON post-quantum signature verification
 * Kernel crypto API integration
 *
 * Based on PQClean reference implementation
 * https://github.com/PQClean/PQClean
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <crypto/akcipher.h>
#include <crypto/internal/akcipher.h>

#include "api.h"
#include "inner.h"

/*
 * FALCON context for kernel crypto API
 * Stores the public key for verification
 */
struct falcon_ctx {
	u8 *public_key;
	unsigned int key_len;
	unsigned int logn;  /* 9 for FALCON-512, 10 for FALCON-1024 */
	bool pub_key_set;
};

/*
 * Set the public key for FALCON verification
 */
static int falcon_set_pub_key(struct crypto_akcipher *tfm, const void *key,
			       unsigned int keylen)
{
	struct falcon_ctx *ctx = akcipher_tfm_ctx(tfm);

	/* FALCON-512: 897 bytes, FALCON-1024: 1793 bytes */
	if (keylen != 897 && keylen != 1793)
		return -EINVAL;

	/* Determine parameter set from key length */
	if (keylen == 897)
		ctx->logn = 9;  /* FALCON-512 */
	else
		ctx->logn = 10; /* FALCON-1024 */

	/* Free old key if exists */
	kfree(ctx->public_key);

	/* Allocate and copy public key */
	ctx->public_key = kmalloc(keylen, GFP_KERNEL);
	if (!ctx->public_key)
		return -ENOMEM;

	memcpy(ctx->public_key, key, keylen);
	ctx->key_len = keylen;
	ctx->pub_key_set = true;

	return 0;
}

/*
 * Verify FALCON signature
 *
 * The signature and message are passed via scatterlists in the akcipher_request.
 * We need to extract them into linear buffers for the FALCON verification function.
 */
static int falcon_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct falcon_ctx *ctx = akcipher_tfm_ctx(tfm);
	unsigned char *buffer = NULL;
	unsigned int sig_len, msg_len, total_len;
	int ret;

	/* Ensure public key is set */
	if (!ctx->pub_key_set)
		return -EINVAL;

	/*
	 * akcipher verify convention: req->src contains [signature || message]
	 * concatenated in a single scatterlist. req->dst is NULL.
	 * req->src_len = signature length, req->dst_len = message length.
	 */
	sig_len = req->src_len;
	msg_len = req->dst_len;
	total_len = sig_len + msg_len;

	/* Validate signature length bounds (CRYPTO_BYTES includes header+nonce) */
	if (ctx->logn == 9 && sig_len > FALCON512_CRYPTO_BYTES)
		return -EINVAL;
	if (ctx->logn == 10 && sig_len > FALCON1024_CRYPTO_BYTES)
		return -EINVAL;

	/* Allocate buffer for combined signature + message */
	buffer = kmalloc(total_len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	/* Extract both signature and message from req->src scatterlist */
	sg_pcopy_to_buffer(req->src,
			   sg_nents_for_len(req->src, total_len),
			   buffer, total_len, 0);

	/* Call FALCON verification with correct parameter set
	 * Returns 0 on success, -1 on verification failure */
	ret = falcon_crypto_sign_verify(
		buffer, sig_len,
		buffer + sig_len, msg_len,
		ctx->public_key, ctx->logn);

	kfree(buffer);

	/* Convert FALCON return code to kernel error code */
	if (ret != 0)
		return -EKEYREJECTED;

	return 0;
}

/*
 * Get maximum signature size
 */
static unsigned int falcon_max_size(struct crypto_akcipher *tfm)
{
	struct falcon_ctx *ctx = akcipher_tfm_ctx(tfm);

	/* Maximum signature size (header + nonce + compressed sig) */
	if (ctx->logn == 9)
		return FALCON512_CRYPTO_BYTES;
	else
		return FALCON1024_CRYPTO_BYTES;
}

/*
 * Clean up FALCON context
 */
static void falcon_exit_tfm(struct crypto_akcipher *tfm)
{
	struct falcon_ctx *ctx = akcipher_tfm_ctx(tfm);

	/* Securely wipe and free public key */
	if (ctx->public_key) {
		memzero_explicit(ctx->public_key, ctx->key_len);
		kfree(ctx->public_key);
		ctx->public_key = NULL;
	}
}

/*
 * FALCON-512 algorithm definition
 */
static struct akcipher_alg falcon512_alg = {
	.verify = falcon_verify,
	.set_pub_key = falcon_set_pub_key,
	.max_size = falcon_max_size,
	.exit = falcon_exit_tfm,
	.base = {
		.cra_name = "falcon-512",
		.cra_driver_name = "falcon-512-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct falcon_ctx),
	},
};

/*
 * FALCON-1024 algorithm definition
 */
static struct akcipher_alg falcon1024_alg = {
	.verify = falcon_verify,
	.set_pub_key = falcon_set_pub_key,
	.max_size = falcon_max_size,
	.exit = falcon_exit_tfm,
	.base = {
		.cra_name = "falcon-1024",
		.cra_driver_name = "falcon-1024-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct falcon_ctx),
	},
};

static void __init falcon_shake256_selftest(void)
{
	/*
	 * SHAKE256("") known answer test.
	 * Expected first 16 bytes:
	 * 46b9dd2b0ba88d13233b3feb743eeb24
	 */
	static const u8 expected[16] = {
		0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
		0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24
	};
	inner_shake256_context sc;
	u8 out[16];

	inner_shake256_init(&sc);
	inner_shake256_flip(&sc);
	inner_shake256_extract(&sc, out, 16);
	inner_shake256_ctx_release(&sc);

	if (memcmp(out, expected, 16) == 0)
		pr_info("falcon: SHAKE256 self-test PASSED\n");
	else
		pr_err("falcon: SHAKE256 self-test FAILED: "
		       "%02x%02x%02x%02x%02x%02x%02x%02x"
		       "%02x%02x%02x%02x%02x%02x%02x%02x\n",
		       out[0], out[1], out[2], out[3],
		       out[4], out[5], out[6], out[7],
		       out[8], out[9], out[10], out[11],
		       out[12], out[13], out[14], out[15]);
}

static int __init falcon_init(void)
{
	int ret;

	falcon_shake256_selftest();

	ret = crypto_register_akcipher(&falcon512_alg);
	if (ret) {
		pr_err("falcon: Failed to register FALCON-512: %d\n", ret);
		return ret;
	}

	ret = crypto_register_akcipher(&falcon1024_alg);
	if (ret) {
		pr_err("falcon: Failed to register FALCON-1024: %d\n", ret);
		crypto_unregister_akcipher(&falcon512_alg);
		return ret;
	}

	pr_info("falcon: FALCON-512 and FALCON-1024 signature verification registered\n");
	return 0;
}

static void __exit falcon_exit(void)
{
	crypto_unregister_akcipher(&falcon1024_alg);
	crypto_unregister_akcipher(&falcon512_alg);
	pr_info("falcon: Unregistered FALCON algorithms\n");
}

module_init(falcon_init);
module_exit(falcon_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FALCON post-quantum signature verification");
MODULE_AUTHOR("Based on PQClean reference implementation");
MODULE_ALIAS_CRYPTO("falcon-512");
MODULE_ALIAS_CRYPTO("falcon-1024");
