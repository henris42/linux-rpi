/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Signature verification
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_VERIFICATION_H
#define _LINUX_VERIFICATION_H

#include <linux/errno.h>
#include <linux/types.h>

/*
 * Indicate that both builtin trusted keys and secondary trusted keys
 * should be used.
 */
#define VERIFY_USE_SECONDARY_KEYRING ((struct key *)1UL)
#define VERIFY_USE_PLATFORM_KEYRING  ((struct key *)2UL)

/*
 * PKCS#7 verification policy flags (caller-selected).
 */
enum verify_pkcs7_flags {
	VERIFY_PKCS7_REQUIRE_CA_TRUST_ANCHOR	= 1U << 0,
	VERIFY_PKCS7_REJECT_SELF_SIGNED_SIGNER	= 1U << 1,
};

static inline int system_keyring_id_check(u64 id)
{
	if (id > (unsigned long)VERIFY_USE_PLATFORM_KEYRING)
		return -EINVAL;

	return 0;
}

/*
 * The use to which an asymmetric key is being put.
 */
enum key_being_used_for {
	VERIFYING_MODULE_SIGNATURE,
	VERIFYING_FIRMWARE_SIGNATURE,
	VERIFYING_KEXEC_PE_SIGNATURE,
	VERIFYING_KEY_SIGNATURE,
	VERIFYING_KEY_SELF_SIGNATURE,
	VERIFYING_UNSPECIFIED_SIGNATURE,
	NR__KEY_BEING_USED_FOR
};
extern const char *const key_being_used_for[NR__KEY_BEING_USED_FOR];

#ifdef CONFIG_SYSTEM_DATA_VERIFICATION

struct key;
struct pkcs7_message;

extern int verify_pkcs7_signature(const void *data, size_t len,
				  const void *raw_pkcs7, size_t pkcs7_len,
				  struct key *trusted_keys,
				  enum key_being_used_for usage,
				  int (*view_content)(void *ctx,
						      const void *data, size_t len,
						      size_t asn1hdrlen),
				  void *ctx);

extern int verify_pkcs7_signature_ext(const void *data, size_t len,
				      const void *raw_pkcs7, size_t pkcs7_len,
				      struct key *trusted_keys,
				      enum key_being_used_for usage,
				      unsigned int flags,
				      int (*view_content)(void *ctx,
							  const void *data, size_t len,
							  size_t asn1hdrlen),
				      void *ctx);

extern int verify_pkcs7_message_sig(const void *data, size_t len,
				    struct pkcs7_message *pkcs7,
				    struct key *trusted_keys,
				    enum key_being_used_for usage,
				    int (*view_content)(void *ctx,
							const void *data,
							size_t len,
							size_t asn1hdrlen),
				    void *ctx);

extern int verify_pkcs7_message_sig_ext(const void *data, size_t len,
					struct pkcs7_message *pkcs7,
					struct key *trusted_keys,
					enum key_being_used_for usage,
					unsigned int flags,
					int (*view_content)(void *ctx,
							    const void *data,
							    size_t len,
							    size_t asn1hdrlen),
					void *ctx);

#ifdef CONFIG_SIGNED_PE_FILE_VERIFICATION
extern int verify_pefile_signature(const void *pebuf, unsigned pelen,
				   struct key *trusted_keys,
				   enum key_being_used_for usage);
#endif

#endif /* CONFIG_SYSTEM_DATA_VERIFICATION */
#endif /* _LINUX_VERIFICATION_H */
