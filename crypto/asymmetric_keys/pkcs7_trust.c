// SPDX-License-Identifier: GPL-2.0-or-later
/* Validate the trust chain of a PKCS#7 message.
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/asn1.h>
#include <linux/key.h>
#include <linux/init.h>
#include <linux/kstrtox.h>
#include <linux/verification.h>
#include <keys/asymmetric-type.h>
#include <crypto/public_key.h>
#include "pkcs7_parser.h"

static bool pkcs7_trust_debug;

static int __init pkcs7_trust_debug_setup(char *str)
{
	bool v;

	if (!str)
		return 0;
	if (kstrtobool(str, &v))
		return 0;
	pkcs7_trust_debug = v;
	return 1;
}
early_param("pkcs7.trust_debug", pkcs7_trust_debug_setup);

static bool asymmetric_key_is_ca(const struct key *key)
{
	const struct public_key *pkey;

	if (!key || key->type != &key_type_asymmetric)
		return false;

	pkey = asymmetric_key_public_key(key);
	if (!pkey)
		return false;

	return test_bit(KEY_EFLAG_CA, &pkey->key_eflags);
}

static void pkcs7tdbg_ring(const struct key *ring, const char *tag)
{
	if (!pkcs7_trust_debug)
		return;

	pr_notice("PKCS7TDBG: ring(%s)=%p serial=%d desc='%s'\n",
		  tag, ring,
		  ring ? ring->serial : -1,
		  (ring && ring->description) ? ring->description : "?");
}

static void pkcs7tdbg_cert(const struct x509_certificate *x509, const char *tag)
{
	if (!pkcs7_trust_debug || !x509)
		return;

	pr_notice("PKCS7TDBG: cert(%s) idx=%u subject='%s'%s\n",
		  tag, x509->index,
		  x509->subject ? x509->subject : "?",
		  (x509->signer == x509) ? " [self-signed]" : "");
}

/*
 * Check the trust on one PKCS#7 SignedInfo block.
 */
static int pkcs7_validate_trust_one(struct pkcs7_message *pkcs7,
				    struct pkcs7_signed_info *sinfo,
				    struct key *trust_keyring,
				    unsigned int flags)
{
	struct public_key_signature *sig = sinfo->sig;
	struct x509_certificate *x509, *last = NULL, *p;
	struct key *key;
	int ret;

	kenter(",%u,", sinfo->index);

	if (pkcs7_trust_debug) {
		pr_notice("PKCS7TDBG: sinfo[%u] flags=0x%x unsupported_crypto=%d\n",
			  sinfo->index, flags, sinfo->unsupported_crypto);
		pkcs7tdbg_ring(trust_keyring, "input");
	}

	if (sinfo->unsupported_crypto) {
		kleave(" = -ENOPKG [cached]");
		return -ENOPKG;
	}

	for (x509 = sinfo->signer; x509; x509 = x509->signer) {
		if (x509->seen) {
			if (x509->verified)
				goto verified;
			kleave(" = -ENOKEY [cached]");
			return -ENOKEY;
		}
		x509->seen = true;

		pkcs7tdbg_cert(x509, "chain");

		/*
		 * Policy: reject any self-signed signer certificate carried in
		 * the PKCS#7 (even if it exists in the trust keyring).
		 */
		if ((flags & VERIFY_PKCS7_REJECT_SELF_SIGNED_SIGNER) &&
		    x509->signer == x509) {
			if (pkcs7_trust_debug)
				pr_notice("PKCS7TDBG: reject self-signed signer cert idx=%u\n",
					  x509->index);
			return -EKEYREJECTED;
		}

		/* Look to see if this certificate is present in the trusted keys. */
		if (pkcs7_trust_debug)
			pr_notice("PKCS7TDBG: find_asymmetric_key(cert idx=%u) in ring serial=%d\n",
				  x509->index, trust_keyring ? trust_keyring->serial : -1);

		key = find_asymmetric_key(trust_keyring,
					  x509->id, x509->skid, NULL, false);

		if (!IS_ERR(key)) {
			if (pkcs7_trust_debug)
				pr_notice("PKCS7TDBG:  HIT key serial=%d desc='%s'\n",
					  key->serial,
					  key->description ? key->description : "?");

			/* Policy: trust anchor must be a CA certificate. */
			if ((flags & VERIFY_PKCS7_REQUIRE_CA_TRUST_ANCHOR) &&
			    !asymmetric_key_is_ca(key)) {
				if (pkcs7_trust_debug)
					pr_notice("PKCS7TDBG:  REJECT matched key is not CA (serial=%d)\n",
						  key->serial);
				key_put(key);
				return -EKEYREJECTED;
			}

			pr_devel("sinfo %u: Cert %u as key %x\n",
				 sinfo->index, x509->index, key_serial(key));
			goto matched;
		}

		if (pkcs7_trust_debug)
			pr_notice("PKCS7TDBG:  MISS err=%ld\n", PTR_ERR(key));

		if (key == ERR_PTR(-ENOMEM))
			return -ENOMEM;

		/* Unknown self-signed: cannot accept. */
		if (x509->signer == x509) {
			kleave(" = -ENOKEY [unknown self-signed]");
			return -ENOKEY;
		}

		might_sleep();
		last = x509;
		sig = last->sig;
	}

	/* No match - see if the root certificate has a signer amongst the trusted keys. */
	if (last && (last->sig->auth_ids[0] || last->sig->auth_ids[1])) {
		if (pkcs7_trust_debug) {
			pkcs7tdbg_cert(last, "root");
			pr_notice("PKCS7TDBG: root backref lookup in ring serial=%d\n",
				  trust_keyring ? trust_keyring->serial : -1);
		}

		key = find_asymmetric_key(trust_keyring,
					  last->sig->auth_ids[0],
					  last->sig->auth_ids[1],
					  NULL, false);
		if (!IS_ERR(key)) {
			if (pkcs7_trust_debug)
				pr_notice("PKCS7TDBG:  ROOT HIT key serial=%d desc='%s'\n",
					  key->serial,
					  key->description ? key->description : "?");

			if ((flags & VERIFY_PKCS7_REQUIRE_CA_TRUST_ANCHOR) &&
			    !asymmetric_key_is_ca(key)) {
				key_put(key);
				return -EKEYREJECTED;
			}

			x509 = last;
			pr_devel("sinfo %u: Root cert %u signer is key %x\n",
				 sinfo->index, x509->index, key_serial(key));
			goto matched;
		}

		if (pkcs7_trust_debug)
			pr_notice("PKCS7TDBG:  ROOT MISS err=%ld\n", PTR_ERR(key));

		if (PTR_ERR(key) != -ENOKEY)
			return PTR_ERR(key);
	}

	/* As a last resort, see if we have a trusted public key that matches the signed info directly. */
	if (pkcs7_trust_debug)
		pr_notice("PKCS7TDBG: direct signer lookup in ring serial=%d\n",
			  trust_keyring ? trust_keyring->serial : -1);

	key = find_asymmetric_key(trust_keyring,
				  sinfo->sig->auth_ids[0], NULL, NULL, false);
	if (!IS_ERR(key)) {
		if (pkcs7_trust_debug)
			pr_notice("PKCS7TDBG:  DIRECT HIT key serial=%d desc='%s'\n",
				  key->serial,
				  key->description ? key->description : "?");

		if ((flags & VERIFY_PKCS7_REQUIRE_CA_TRUST_ANCHOR) &&
		    !asymmetric_key_is_ca(key)) {
			key_put(key);
			return -EKEYREJECTED;
		}

		pr_devel("sinfo %u: Direct signer is key %x\n",
			 sinfo->index, key_serial(key));
		x509 = NULL;
		sig = sinfo->sig;
		goto matched;
	}

	if (pkcs7_trust_debug)
		pr_notice("PKCS7TDBG:  DIRECT MISS err=%ld\n", PTR_ERR(key));

	if (PTR_ERR(key) != -ENOKEY)
		return PTR_ERR(key);

	kleave(" = -ENOKEY [no backref]");
	return -ENOKEY;

matched:
	ret = verify_signature(key, sig);
	key_put(key);
	if (ret < 0) {
		if (ret == -ENOMEM)
			return ret;
		kleave(" = -EKEYREJECTED [verify %d]", ret);
		return -EKEYREJECTED;
	}

verified:
	if (x509) {
		x509->verified = true;
		for (p = sinfo->signer; p != x509; p = p->signer)
			p->verified = true;
	}
	kleave(" = 0");
	return 0;
}

int pkcs7_validate_trust_ext(struct pkcs7_message *pkcs7,
			     struct key *trust_keyring,
			     unsigned int flags)
{
	struct pkcs7_signed_info *sinfo;
	struct x509_certificate *p;
	int cached_ret = -ENOKEY;
	int ret;

	for (p = pkcs7->certs; p; p = p->next)
		p->seen = false;

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		ret = pkcs7_validate_trust_one(pkcs7, sinfo, trust_keyring, flags);
		switch (ret) {
		case -ENOKEY:
			continue;
		case -ENOPKG:
			if (cached_ret == -ENOKEY)
				cached_ret = -ENOPKG;
			continue;
		case 0:
			cached_ret = 0;
			continue;
		default:
			return ret;
		}
	}

	return cached_ret;
}
EXPORT_SYMBOL_GPL(pkcs7_validate_trust_ext);

int pkcs7_validate_trust(struct pkcs7_message *pkcs7,
			 struct key *trust_keyring)
{
	return pkcs7_validate_trust_ext(pkcs7, trust_keyring, 0);
}
EXPORT_SYMBOL_GPL(pkcs7_validate_trust);