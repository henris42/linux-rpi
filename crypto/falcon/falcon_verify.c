// SPDX-License-Identifier: GPL-2.0
/*
 * FALCON post-quantum signature verification
 * Kernel crypto API integration (STUB - work in progress)
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
	unsigned char *sig_buf = NULL;
	unsigned char *msg_buf = NULL;
	unsigned int sig_len, msg_len;
	int ret;

	/* Ensure public key is set */
	if (!ctx->pub_key_set)
		return -EINVAL;

	/* Get lengths from request */
	sig_len = req->src_len;
	msg_len = req->dst_len;

	/* Validate signature length bounds */
	if (ctx->logn == 9 && sig_len > 690)
		return -EINVAL;  /* FALCON-512 max */
	if (ctx->logn == 10 && sig_len > 1280)
		return -EINVAL;  /* FALCON-1024 max */

	/* Allocate buffers for signature and message */
	sig_buf = kmalloc(sig_len, GFP_KERNEL);
	if (!sig_buf)
		return -ENOMEM;

	msg_buf = kmalloc(msg_len, GFP_KERNEL);
	if (!msg_buf) {
		kfree(sig_buf);
		return -ENOMEM;
	}

	/* Extract signature from scatterlist */
	sg_copy_to_buffer(req->src, sg_nents_for_len(req->src, sig_len),
			  sig_buf, sig_len);

	/* Extract message from scatterlist */
	sg_copy_to_buffer(req->dst, sg_nents_for_len(req->dst, msg_len),
			  msg_buf, msg_len);

	/* Call FALCON verification
	 * Returns 0 on success, -1 on verification failure */
	ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
		sig_buf, sig_len,
		msg_buf, msg_len,
		ctx->public_key);

	/* Clean up buffers */
	kfree(sig_buf);
	kfree(msg_buf);

	/* Convert FALCON return code to kernel error code */
	if (ret != 0)
		return -EKEYREJECTED;  /* Signature verification failed */

	return 0;  /* Success */
}

/*
 * Get maximum signature size
 */
static unsigned int falcon_max_size(struct crypto_akcipher *tfm)
{
	struct falcon_ctx *ctx = akcipher_tfm_ctx(tfm);

	/* Maximum compressed signature size */
	if (ctx->logn == 9)
		return 690;   /* FALCON-512 */
	else
		return 1280;  /* FALCON-1024 */
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

static int __init falcon_init(void)
{
	int ret;

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
