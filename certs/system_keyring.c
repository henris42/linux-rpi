// SPDX-License-Identifier: GPL-2.0-or-later
/* System trusted keyring for trusted public keys
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/verification.h>
#include <linux/init.h>
#include <linux/kstrtox.h>
#include "secondary_trusted_keys.h"
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include <crypto/pkcs7.h>

static struct key *builtin_trusted_keys;
#ifdef CONFIG_SECONDARY_TRUSTED_KEYRING
static struct key *secondary_trusted_keys;
#endif
#ifdef CONFIG_INTEGRITY_MACHINE_KEYRING
static struct key *machine_trusted_keys;
#endif
#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
static struct key *platform_trusted_keys;
#endif
#ifdef CONFIG_BOOT_CERTS_SYSFS
static struct key *boot_root_certs;
#endif

extern __initconst const u8 system_certificate_list[];
extern __initconst const unsigned long system_certificate_list_size;
extern __initconst const unsigned long module_cert_size;


/* Debug instrumentation for PKCS#7 verification path.
 * Enable via kernel cmdline: system_keyring.pkcs7_debug=1
 * Optionally increase verbosity: system_keyring.pkcs7_debug_verbose=1
 */
static bool pkcs7_debug;
static bool pkcs7_debug_verbose;

static int __init system_keyring_pkcs7_debug_setup(char *str)
{
	bool v;

	if (!str)
		return 0;
	if (kstrtobool(str, &v))
		return 0;
	pkcs7_debug = v;
	return 1;
}
early_param("system_keyring.pkcs7_debug", system_keyring_pkcs7_debug_setup);

static int __init system_keyring_pkcs7_debug_verbose_setup(char *str)
{
	bool v;

	if (!str)
		return 0;
	if (kstrtobool(str, &v))
		return 0;
	pkcs7_debug_verbose = v;
	return 1;
}
early_param("system_keyring.pkcs7_debug_verbose", system_keyring_pkcs7_debug_verbose_setup);

static const char *keyring_name(struct key *k)
{
	if (k == builtin_trusted_keys)
		return "builtin";
#ifdef CONFIG_SECONDARY_TRUSTED_KEYRING
	if (k == secondary_trusted_keys)
		return "secondary";
#endif
#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
	if (k == platform_trusted_keys)
		return "platform";
#endif
#ifdef CONFIG_INTEGRITY_MACHINE_KEYRING
	if (k == machine_trusted_keys)
		return "machine";
#endif
	return "other";
}

static void pkcs7dbg_log_keyring_sel(struct key *orig, struct key *sel)
{
	if (!pkcs7_debug)
		return;

	pr_notice("PKCS7DBG: trusted_keys arg=%p selected=%p(%s)%s\n",
		  orig, sel, keyring_name(sel),
		  sel ? "" : " [NULL]");
	if (pkcs7_debug_verbose && sel)
		pr_notice("PKCS7DBG: selected keyring serial=%d desc='%s'\n",
			  sel->serial, sel->description ? sel->description : "?");
}

static void pkcs7dbg_log_rc(const char *stage, int rc)
{
	if (!pkcs7_debug)
		return;

	pr_notice("PKCS7DBG: %s -> %d\n", stage, rc);
}

static void pkcs7dbg_log_usage_flags(enum key_being_used_for usage,
				     unsigned int flags,
				     const void *data, size_t len,
				     const void *pkcs7)
{
	if (!pkcs7_debug)
		return;

	pr_notice("PKCS7DBG: enter usage=%s(%d) flags=0x%x data=%p len=%zu pkcs7=%p\n",
		  key_being_used_for[usage], usage, flags, data, len, pkcs7);
}

/**
 * restrict_link_by_builtin_trusted - Restrict keyring addition by built-in CA
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @restriction_key: A ring of keys that can be used to vouch for the new cert.
 *
 * Restrict the addition of keys into a keyring based on the key-to-be-added
 * being vouched for by a key in the built in system keyring.
 */
int restrict_link_by_builtin_trusted(struct key *dest_keyring,
				     const struct key_type *type,
				     const union key_payload *payload,
				     struct key *restriction_key)
{
	return restrict_link_by_signature(dest_keyring, type, payload,
					  builtin_trusted_keys);
}

/**
 * restrict_link_by_digsig_builtin - Restrict digitalSignature key additions by the built-in keyring
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @restriction_key: A ring of keys that can be used to vouch for the new cert.
 *
 * Restrict the addition of keys into a keyring based on the key-to-be-added
 * being vouched for by a key in the built in system keyring. The new key
 * must have the digitalSignature usage field set.
 */
int restrict_link_by_digsig_builtin(struct key *dest_keyring,
				    const struct key_type *type,
				    const union key_payload *payload,
				    struct key *restriction_key)
{
	return restrict_link_by_digsig(dest_keyring, type, payload,
				       builtin_trusted_keys);
}

#ifdef CONFIG_SECONDARY_TRUSTED_KEYRING
/**
 * restrict_link_by_builtin_and_secondary_trusted - Restrict keyring
 *   addition by both built-in and secondary keyrings.
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @restrict_key: A ring of keys that can be used to vouch for the new cert.
 *
 * Restrict the addition of keys into a keyring based on the key-to-be-added
 * being vouched for by a key in either the built-in or the secondary system
 * keyrings.
 */
int restrict_link_by_builtin_and_secondary_trusted(
	struct key *dest_keyring,
	const struct key_type *type,
	const union key_payload *payload,
	struct key *restrict_key)
{
	/* If we have a secondary trusted keyring, then that contains a link
	 * through to the builtin keyring and the search will follow that link.
	 */
	if (type == &key_type_keyring &&
	    dest_keyring == secondary_trusted_keys &&
	    payload == &builtin_trusted_keys->payload)
		/* Allow the builtin keyring to be added to the secondary */
		return 0;

	return restrict_link_by_signature(dest_keyring, type, payload,
					  secondary_trusted_keys);
}

/**
 * restrict_link_by_digsig_builtin_and_secondary - Restrict by digitalSignature.
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @restrict_key: A ring of keys that can be used to vouch for the new cert.
 *
 * Restrict the addition of keys into a keyring based on the key-to-be-added
 * being vouched for by a key in either the built-in or the secondary system
 * keyrings. The new key must have the digitalSignature usage field set.
 */
int restrict_link_by_digsig_builtin_and_secondary(struct key *dest_keyring,
						  const struct key_type *type,
						  const union key_payload *payload,
						  struct key *restrict_key)
{
	/* If we have a secondary trusted keyring, then that contains a link
	 * through to the builtin keyring and the search will follow that link.
	 */
	if (type == &key_type_keyring &&
	    dest_keyring == secondary_trusted_keys &&
	    payload == &builtin_trusted_keys->payload)
		/* Allow the builtin keyring to be added to the secondary */
		return 0;

	return restrict_link_by_digsig(dest_keyring, type, payload,
				       secondary_trusted_keys);
}

/*
 * Allocate a struct key_restriction for the "builtin and secondary trust"
 * keyring. Only for use in system_trusted_keyring_init().
 */
#if !IS_ENABLED(CONFIG_BOOT_CERTS_SYSFS)
static __init struct key_restriction *get_builtin_and_secondary_restriction(void)
{
	struct key_restriction *restriction;

	restriction = kzalloc(sizeof(struct key_restriction), GFP_KERNEL);

	if (!restriction)
		panic("Can't allocate secondary trusted keyring restriction\n");

	if (IS_ENABLED(CONFIG_INTEGRITY_MACHINE_KEYRING))
		restriction->check = restrict_link_by_builtin_secondary_and_machine;
	else
		restriction->check = restrict_link_by_builtin_and_secondary_trusted;

	return restriction;
}
#endif

/**
 * add_to_secondary_keyring - Add to secondary keyring.
 * @source: Source of key
 * @data: The blob holding the key
 * @len: The length of the data blob
 *
 * Add a key to the secondary keyring. The key must be vouched for by a key in the builtin,
 * machine or secondary keyring itself.
 */
void __init add_to_secondary_keyring(const char *source, const void *data, size_t len)
{
	key_ref_t key;
	key_perm_t perm;

	perm = (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_VIEW;

	key = key_create_or_update(make_key_ref(secondary_trusted_keys, 1),
				   "asymmetric",
				   NULL, data, len, perm,
				   KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key)) {
		pr_err("Problem loading X.509 certificate from %s to secondary keyring %ld\n",
		       source, PTR_ERR(key));
		return;
	}

	pr_notice("Loaded X.509 cert '%s'\n", key_ref_to_ptr(key)->description);
	key_ref_put(key);
}

/*
 * Add a DER-encoded X.509 certificate to .secondary_trusted_keys
 * as an "asymmetric" key. The asymmetric preparse will validate
 * and create the key if acceptable.
 */
int secondary_trusted_keys_add_cert(const void *der, size_t der_len,
				   const char *desc)
{
	key_ref_t keyring_ref;
	key_ref_t key_ref;

	if (!secondary_trusted_keys)
		return -ENOKEY;
	if (!der || der_len == 0 || !desc)
		return -EINVAL;

	keyring_ref = make_key_ref(secondary_trusted_keys, 1);

	key_ref = key_create_or_update(keyring_ref,
				       "asymmetric",
				       desc,
				       der,
				       der_len,
				       KEY_POS_ALL | KEY_USR_VIEW,
				       KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key_ref))
		return PTR_ERR(key_ref);

	/* Drop the ref we got back. */
	key_ref_put(key_ref);
	return 0;
}
EXPORT_SYMBOL_GPL(secondary_trusted_keys_add_cert);
/*
 * Deny linking any key into the destination keyring.
 * Prototype comes from key_restrict_link_func_t (check include/linux/key-type.h).
 */
static int restrict_link_deny(struct key *dest_keyring,
			      const struct key_type *type,
			      const union key_payload *payload,
			      struct key *trust_keyring)
{
	return -EACCES;
}

static const struct key_restriction secondary_trusted_keys_deny_restrict = {
	.check = restrict_link_deny,
};

/*
 * Add a DER-encoded X.509 certificate to the .boot_root_certs keyring.
 * This keyring holds only root CA certificates for boot chain validation.
 */
int boot_root_certs_add_cert(const void *der, size_t der_len, const char *desc)
{
#if !IS_ENABLED(CONFIG_BOOT_CERTS_SYSFS)
	return -EOPNOTSUPP;
#else
	key_ref_t keyring_ref;
	key_ref_t key_ref;

	if (!boot_root_certs)
		return -ENOKEY;
	if (!der || der_len == 0 || !desc)
		return -EINVAL;

	keyring_ref = make_key_ref(boot_root_certs, 1);

	key_ref = key_create_or_update(keyring_ref,
				       "asymmetric",
				       desc,
				       der,
				       der_len,
				       KEY_POS_ALL | KEY_USR_VIEW,
				       KEY_ALLOC_NOT_IN_QUOTA |
				       KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key_ref))
		return PTR_ERR(key_ref);

	key_ref_put(key_ref);
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(boot_root_certs_add_cert);

int secondary_trusted_keys_seal(void)
{
#if !IS_ENABLED(CONFIG_BOOT_CERTS_SYSFS)
	return -EOPNOTSUPP;
#else
	key_ref_t keyring_ref;
	key_ref_t boot_root_ref;
	char restr[64];
	int ret;

	if (!secondary_trusted_keys)
		return -ENOKEY;

	/*
	 * Hierarchical sealing strategy:
	 * 1. Seal boot_root_certs to prevent new root CAs
	 * 2. Restrict secondary_trusted_keys to only accept certs signed by boot_root_certs
	 *
	 * This allows intermediate CAs to be added if signed by a root CA,
	 * but prevents any new root CAs from being added.
	 */

	/* Step 1: Seal the boot root keyring (no new roots allowed) */
	if (boot_root_certs) {
		boot_root_ref = make_key_ref(boot_root_certs, 1);
		ret = keyring_restrict(boot_root_ref, NULL, NULL);
		if (ret && ret != -EEXIST) {
			pr_err("boot_root_certs: failed to seal root keyring (err=%d)\n", ret);
			return ret;
		}
		pr_notice("boot_root_certs: sealed (no new root CAs allowed)\n");
	}

	/* Step 2: Restrict secondary to only accept certs signed by boot roots */
	if (boot_root_certs) {
		keyring_ref = make_key_ref(secondary_trusted_keys, 1);

		/*
		 * Use key_or_keyring restriction (NOT chain).
		 * This validates new certs against boot_root_certs only,
		 * NOT against keys already in secondary_trusted_keys.
		 * This ensures only root CAs can sign new certificates.
		 */
		snprintf(restr, sizeof(restr), "key_or_keyring:%u",
			 boot_root_certs->serial);

		ret = keyring_restrict(keyring_ref, "asymmetric", restr);
		if (ret == 0 || ret == -EEXIST) {
			pr_notice("secondary_trusted_keys: sealed (accepts only boot root CA-signed certs)\n");
			return 0;
		}

		if (ret == -EINVAL) {
			pr_warn("secondary_trusted_keys: 'key_or_keyring' restriction unsupported\n");
			return ret;
		}

		return ret;
	}

	/* Fallback: No boot_root_certs, seal completely */
	keyring_ref = make_key_ref(secondary_trusted_keys, 1);
	ret = keyring_restrict(keyring_ref, NULL, NULL);
	if (ret == 0 || ret == -EEXIST) {
		pr_notice("secondary_trusted_keys: sealed (no boot roots, fully locked)\n");
		return 0;
	}

	return ret;
#endif
}
EXPORT_SYMBOL_GPL(secondary_trusted_keys_seal);

#endif
#ifdef CONFIG_INTEGRITY_MACHINE_KEYRING
void __init set_machine_trusted_keys(struct key *keyring)
{
	machine_trusted_keys = keyring;

	if (key_link(secondary_trusted_keys, machine_trusted_keys) < 0)
		panic("Can't link (machine) trusted keyrings\n");
}

/**
 * restrict_link_by_builtin_secondary_and_machine - Restrict keyring addition.
 * @dest_keyring: Keyring being linked to.
 * @type: The type of key being added.
 * @payload: The payload of the new key.
 * @restrict_key: A ring of keys that can be used to vouch for the new cert.
 *
 * Restrict the addition of keys into a keyring based on the key-to-be-added
 * being vouched for by a key in either the built-in, the secondary, or
 * the machine keyrings.
 */
int restrict_link_by_builtin_secondary_and_machine(
	struct key *dest_keyring,
	const struct key_type *type,
	const union key_payload *payload,
	struct key *restrict_key)
{
	if (machine_trusted_keys && type == &key_type_keyring &&
	    dest_keyring == secondary_trusted_keys &&
	    payload == &machine_trusted_keys->payload)
		/* Allow the machine keyring to be added to the secondary */
		return 0;

	return restrict_link_by_builtin_and_secondary_trusted(dest_keyring, type,
							      payload, restrict_key);
}
#endif

/*
 * Create the trusted keyrings
 */
static __init int system_trusted_keyring_init(void)
{
	pr_notice("Initialise system trusted keyrings\n");

	builtin_trusted_keys =
		keyring_alloc(".builtin_trusted_keys",
			      GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			      KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL, NULL);
	if (IS_ERR(builtin_trusted_keys))
		panic("Can't allocate builtin trusted keyring\n");

#ifdef CONFIG_SECONDARY_TRUSTED_KEYRING
secondary_trusted_keys =
	keyring_alloc(".secondary_trusted_keys",
		      GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
		      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
		       KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH |
		       KEY_USR_WRITE),
		      KEY_ALLOC_NOT_IN_QUOTA,
#if IS_ENABLED(CONFIG_BOOT_CERTS_SYSFS)
		      NULL,   /* boot_certs will populate + seal */
#else
		      get_builtin_and_secondary_restriction(),
#endif
		      NULL);
	if (IS_ERR(secondary_trusted_keys))
		panic("Can't allocate secondary trusted keyring\n");

	if (key_link(secondary_trusted_keys, builtin_trusted_keys) < 0)
		panic("Can't link trusted keyrings\n");

#if IS_ENABLED(CONFIG_BOOT_CERTS_SYSFS)
	/*
	 * Create a separate keyring for boot root certificates.
	 * This keyring will contain only self-signed root CAs from the boot chain.
	 * It will be sealed separately to prevent new root CAs being added,
	 * while secondary_trusted_keys can still accept intermediate CAs
	 * signed by these roots.
	 */
	boot_root_certs =
		keyring_alloc(".boot_root_certs",
			      GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			      ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
			       KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH),
			      KEY_ALLOC_NOT_IN_QUOTA,
			      NULL,   /* No restriction yet - boot_certs will populate then seal */
			      NULL);
	if (IS_ERR(boot_root_certs))
		panic("Can't allocate boot_root_certs keyring\n");

	pr_notice("Boot root certificate keyring initialized\n");
#endif

#endif

	return 0;
}

/*
 * Must be initialised before we try and load the keys into the keyring.
 */
device_initcall(system_trusted_keyring_init);

__init int load_module_cert(struct key *keyring)
{
	if (!IS_ENABLED(CONFIG_IMA_APPRAISE_MODSIG))
		return 0;

	pr_notice("Loading compiled-in module X.509 certificates\n");

	return x509_load_certificate_list(system_certificate_list,
					  module_cert_size, keyring);
}

/*
 * Load the compiled-in list of X.509 certificates.
 */
static __init int load_system_certificate_list(void)
{
	const u8 *p;
	unsigned long size;

	pr_notice("Loading compiled-in X.509 certificates\n");

#ifdef CONFIG_MODULE_SIG
	p = system_certificate_list;
	size = system_certificate_list_size;
#else
	p = system_certificate_list + module_cert_size;
	size = system_certificate_list_size - module_cert_size;
#endif

	return x509_load_certificate_list(p, size, builtin_trusted_keys);
}
late_initcall(load_system_certificate_list);

#ifdef CONFIG_SYSTEM_DATA_VERIFICATION

/**
 * verify_pkcs7_message_sig - Verify a PKCS#7-based signature on system data.
 * @data: The data to be verified (NULL if expecting internal data).
 * @len: Size of @data.
 * @pkcs7: The PKCS#7 message that is the signature.
 * @trusted_keys: Trusted keys to use (NULL for builtin trusted keys only,
 *					(void *)1UL for all trusted keys).
 * @usage: The use to which the key is being put.
 * @view_content: Callback to gain access to content.
 * @ctx: Context for callback.
 */

static int __verify_pkcs7_message_sig(const void *data, size_t len,
				      struct pkcs7_message *pkcs7,
				      struct key *trusted_keys,
				      enum key_being_used_for usage,
				      unsigned int flags,
				      int (*view_content)(void *ctx,
							  const void *data, size_t len,
							  size_t asn1hdrlen),
				      void *ctx)
{
	int ret;
	struct key *selected = trusted_keys;

	pkcs7dbg_log_usage_flags(usage, flags, data, len, pkcs7);

	/* The data should be detached - so we need to supply it. */
	if (data && pkcs7_supply_detached_data(pkcs7, data, len) < 0) {
		pr_err("PKCS#7 signature with non-detached data\n");
		ret = -EBADMSG;
		pkcs7dbg_log_rc("pkcs7_supply_detached_data", ret);
		goto error;
	}

	ret = pkcs7_verify(pkcs7, usage);
	pkcs7dbg_log_rc("pkcs7_verify", ret);
	if (ret < 0)
		goto error;

	ret = is_key_on_revocation_list(pkcs7);
	pkcs7dbg_log_rc("is_key_on_revocation_list", ret);
	if (ret != -ENOKEY) {
		pr_devel("PKCS#7 key is on revocation list\n");
		goto error;
	}

	if (!trusted_keys) {
		selected = builtin_trusted_keys;
	} else if (trusted_keys == VERIFY_USE_SECONDARY_KEYRING) {
#ifdef CONFIG_SECONDARY_TRUSTED_KEYRING
		selected = secondary_trusted_keys;
#else
		selected = builtin_trusted_keys;
#endif
	} else if (trusted_keys == VERIFY_USE_PLATFORM_KEYRING) {
#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
		selected = platform_trusted_keys;
#else
		selected = NULL;
#endif
		if (!selected) {
			ret = -ENOKEY;
			pr_devel("PKCS#7 platform keyring is not available\n");
			pkcs7dbg_log_rc("select_platform_keyring", ret);
			goto error;
		}
	} else {
		selected = trusted_keys;
	}

	pkcs7dbg_log_keyring_sel(trusted_keys, selected);

	ret = pkcs7_validate_trust_ext(pkcs7, selected, flags);
	pkcs7dbg_log_rc("pkcs7_validate_trust_ext", ret);

	if (ret < 0) {
		if (ret == -ENOKEY)
			pr_devel("PKCS#7 signature not signed with a trusted key\n");
		goto error;
	}

	if (view_content) {
		size_t asn1hdrlen;
		const void *cdata = NULL;
		size_t clen = 0;

		ret = pkcs7_get_content_data(pkcs7, &cdata, &clen, &asn1hdrlen);
		pkcs7dbg_log_rc("pkcs7_get_content_data", ret);
		if (pkcs7_debug && pkcs7_debug_verbose && ret == 0)
			pr_notice("PKCS7DBG: content len=%zu asn1hdrlen=%zu\n",
				  clen, asn1hdrlen);

		if (ret < 0) {
			if (ret == -ENODATA)
				pr_devel("PKCS#7 message does not contain data\n");
			goto error;
		}

		ret = view_content(ctx, cdata, clen, asn1hdrlen);
		pkcs7dbg_log_rc("view_content", ret);
	}

error:
	if (pkcs7_debug)
		pr_notice("PKCS7DBG: exit ret=%d usage=%s flags=0x%x\n",
			  ret, key_being_used_for[usage], flags);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}

int verify_pkcs7_message_sig_ext(const void *data, size_t len,
				 struct pkcs7_message *pkcs7,
				 struct key *trusted_keys,
				 enum key_being_used_for usage,
				 unsigned int flags,
				 int (*view_content)(void *ctx,
						     const void *data, size_t len,
						     size_t asn1hdrlen),
				 void *ctx)
{
	return __verify_pkcs7_message_sig(data, len, pkcs7, trusted_keys, usage,
					  flags, view_content, ctx);
}
EXPORT_SYMBOL_GPL(verify_pkcs7_message_sig_ext);

int verify_pkcs7_message_sig(const void *data, size_t len,
			     struct pkcs7_message *pkcs7,
			     struct key *trusted_keys,
			     enum key_being_used_for usage,
			     int (*view_content)(void *ctx,
						 const void *data, size_t len,
						 size_t asn1hdrlen),
			     void *ctx)
{
	return __verify_pkcs7_message_sig(data, len, pkcs7, trusted_keys, usage,
					  0, view_content, ctx);
}

/**
 * verify_pkcs7_signature - Verify a PKCS#7-based signature on system data.
 * @data: The data to be verified (NULL if expecting internal data).
 * @len: Size of @data.
 * @raw_pkcs7: The PKCS#7 message that is the signature.
 * @pkcs7_len: The size of @raw_pkcs7.
 * @trusted_keys: Trusted keys to use (NULL for builtin trusted keys only,
 *					(void *)1UL for all trusted keys).
 * @usage: The use to which the key is being put.
 * @view_content: Callback to gain access to content.
 * @ctx: Context for callback.
 */
int verify_pkcs7_signature(const void *data, size_t len,
			   const void *raw_pkcs7, size_t pkcs7_len,
			   struct key *trusted_keys,
			   enum key_being_used_for usage,
			   int (*view_content)(void *ctx,
					       const void *data, size_t len,
					       size_t asn1hdrlen),
			   void *ctx)
{
	struct pkcs7_message *pkcs7;
	int ret;

	pkcs7 = pkcs7_parse_message(raw_pkcs7, pkcs7_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = __verify_pkcs7_message_sig(data, len, pkcs7, trusted_keys, usage,
					 0, view_content, ctx);

	pkcs7_free_message(pkcs7);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(verify_pkcs7_signature);

int verify_pkcs7_signature_ext(const void *data, size_t len,
			       const void *raw_pkcs7, size_t pkcs7_len,
			       struct key *trusted_keys,
			       enum key_being_used_for usage,
			       unsigned int flags,
			       int (*view_content)(void *ctx,
						   const void *data, size_t len,
						   size_t asn1hdrlen),
			       void *ctx)
{
	struct pkcs7_message *pkcs7;
	int ret;

	pkcs7 = pkcs7_parse_message(raw_pkcs7, pkcs7_len);
	if (IS_ERR(pkcs7))
		return PTR_ERR(pkcs7);

	ret = __verify_pkcs7_message_sig(data, len, pkcs7, trusted_keys, usage,
					 flags, view_content, ctx);

	pkcs7_free_message(pkcs7);
	return ret;
}
EXPORT_SYMBOL_GPL(verify_pkcs7_signature_ext);

#endif /* CONFIG_SYSTEM_DATA_VERIFICATION */

#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
void __init set_platform_trusted_keys(struct key *keyring)
{
	platform_trusted_keys = keyring;
}
#endif
