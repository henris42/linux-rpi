/* Sign a module file using the given key.
 *
 * Copyright © 2014-2016 Red Hat, Inc. All Rights Reserved.
 * Copyright © 2015      Intel Corporation.
 * Copyright © 2016      Hewlett Packard Enterprise Development LP
 *
 * Authors: David Howells <dhowells@redhat.com>
 *          David Woodhouse <dwmw2@infradead.org>
 *          Juerg Haefliger <juerg.haefliger@hpe.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the licence, or (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <err.h>
#include <arpa/inet.h>
#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_MAJOR >= 3
# define USE_PKCS11_PROVIDER
# include <openssl/provider.h>
# include <openssl/store.h>
#else
# if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_DEPRECATED_3_0)
#  define USE_PKCS11_ENGINE
#  include <openssl/engine.h>
# endif
#endif
#include "ssl-common.h"

/*
 * Use CMS if we have openssl-1.0.0 or newer available - otherwise we have to
 * assume that it's not available and its header file is missing and that we
 * should use PKCS#7 instead.  Switching to the older PKCS#7 format restricts
 * the options we have on specifying the X.509 certificate we want.
 *
 * Further, older versions of OpenSSL don't support manually adding signers to
 * the PKCS#7 message so have to accept that we get a certificate included in
 * the signature message.  Nor do such older versions of OpenSSL support
 * signing with anything other than SHA1 - so we're stuck with that if such is
 * the case.
 */
#if defined(LIBRESSL_VERSION_NUMBER) || \
	OPENSSL_VERSION_NUMBER < 0x10000000L || \
	defined(OPENSSL_NO_CMS)
#define USE_PKCS7
#endif
#ifndef USE_PKCS7
#include <openssl/cms.h>
#else
#include <openssl/pkcs7.h>
#endif

struct module_signature {
	uint8_t		algo;		/* Public-key crypto algorithm [0] */
	uint8_t		hash;		/* Digest algorithm [0] */
	uint8_t		id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	uint8_t		signer_len;	/* Length of signer's name [0] */
	uint8_t		key_id_len;	/* Length of key identifier [0] */
	uint8_t		__pad[3];
	uint32_t	sig_len;	/* Length of signature data */
};

#define PKEY_ID_PKCS7 2

static char magic_number[] = "~Module signature appended~\n";

static __attribute__((noreturn))
void format(void)
{
	fprintf(stderr,
		"Usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]\n");
	fprintf(stderr,
		"       scripts/sign-file -s <raw sig> <hash algo> <x509> <module> [<dest>]\n");
	exit(2);
}

static const char *key_pass;

static int pem_pw_cb(char *buf, int len, int w, void *v)
{
	int pwlen;

	if (!key_pass)
		return -1;

	pwlen = strlen(key_pass);
	if (pwlen >= len)
		return -1;

	strcpy(buf, key_pass);

	/* If it's wrong, don't keep trying it. */
	key_pass = NULL;

	return pwlen;
}

static EVP_PKEY *read_private_key_pkcs11(const char *private_key_name)
{
	EVP_PKEY *private_key = NULL;
#ifdef USE_PKCS11_PROVIDER
	OSSL_STORE_CTX *store;

	if (!OSSL_PROVIDER_try_load(NULL, "pkcs11", true))
		ERR(1, "OSSL_PROVIDER_try_load(pkcs11)");
	if (!OSSL_PROVIDER_try_load(NULL, "default", true))
		ERR(1, "OSSL_PROVIDER_try_load(default)");

	store = OSSL_STORE_open(private_key_name, NULL, NULL, NULL, NULL);
	ERR(!store, "OSSL_STORE_open");

	while (!OSSL_STORE_eof(store)) {
		OSSL_STORE_INFO *info = OSSL_STORE_load(store);

		if (!info) {
			drain_openssl_errors(__LINE__, 0);
			continue;
		}
		if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
			private_key = OSSL_STORE_INFO_get1_PKEY(info);
			ERR(!private_key, "OSSL_STORE_INFO_get1_PKEY");
		}
		OSSL_STORE_INFO_free(info);
		if (private_key)
			break;
	}
	OSSL_STORE_close(store);
#elif defined(USE_PKCS11_ENGINE)
	ENGINE *e;

	ENGINE_load_builtin_engines();
	drain_openssl_errors(__LINE__, 1);
	e = ENGINE_by_id("pkcs11");
	ERR(!e, "Load PKCS#11 ENGINE");
	if (ENGINE_init(e))
		drain_openssl_errors(__LINE__, 1);
	else
		ERR(1, "ENGINE_init");
	if (key_pass)
		ERR(!ENGINE_ctrl_cmd_string(e, "PIN", key_pass, 0), "Set PKCS#11 PIN");
	private_key = ENGINE_load_private_key(e, private_key_name, NULL, NULL);
	ERR(!private_key, "%s", private_key_name);
#else
	fprintf(stderr, "no pkcs11 engine/provider available\n");
	exit(1);
#endif
	return private_key;
}

static EVP_PKEY *read_private_key(const char *private_key_name)
{
	if (!strncmp(private_key_name, "pkcs11:", 7)) {
		return read_private_key_pkcs11(private_key_name);
	} else {
		EVP_PKEY *private_key;
		BIO *b;

		b = BIO_new_file(private_key_name, "rb");
		ERR(!b, "%s", private_key_name);
		private_key = PEM_read_bio_PrivateKey(b, NULL, pem_pw_cb,
						      NULL);
		ERR(!private_key, "%s", private_key_name);
		BIO_free(b);

		return private_key;
	}
}

static X509 *read_x509(const char *x509_name)
{
	unsigned char buf[2];
	X509 *x509;
	BIO *b;
	int n;

	b = BIO_new_file(x509_name, "rb");
	ERR(!b, "%s", x509_name);

	/* Look at the first two bytes of the file to determine the encoding */
	n = BIO_read(b, buf, 2);
	if (n != 2) {
		if (BIO_should_retry(b)) {
			fprintf(stderr, "%s: Read wanted retry\n", x509_name);
			exit(1);
		}
		if (n >= 0) {
			fprintf(stderr, "%s: Short read\n", x509_name);
			exit(1);
		}
		ERR(1, "%s", x509_name);
	}

	ERR(BIO_reset(b) != 0, "%s", x509_name);

	if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
		/* Assume raw DER encoded X.509 */
		x509 = d2i_X509_bio(b, NULL);
	else
		/* Assume PEM encoded X.509 */
		x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);

	BIO_free(b);
	ERR(!x509, "%s", x509_name);

	return x509;
}

/*
 * ========================================================================
 * PQC (Post-Quantum Cryptography) PKCS#7 construction
 *
 * OpenSSL's CMS layer doesn't support PQC key types (NID=-1 for FALCON
 * etc). We bypass CMS entirely: use EVP_DigestSign for the raw signature,
 * then manually construct a minimal PKCS#7 SignedData DER structure that
 * the kernel's PKCS#7 parser can verify.
 * ========================================================================
 */

#if OPENSSL_VERSION_MAJOR >= 3

/* DER helper: compute encoded length field size */
static size_t der_len_size(size_t len)
{
	if (len < 0x80)    return 1;
	if (len < 0x100)   return 2;
	if (len < 0x10000) return 3;
	return 4;
}

/* DER helper: write length field, return pointer past written bytes */
static unsigned char *der_put_length(unsigned char *p, size_t len)
{
	if (len < 0x80) {
		*p++ = (unsigned char)len;
	} else if (len < 0x100) {
		*p++ = 0x81;
		*p++ = (unsigned char)len;
	} else if (len < 0x10000) {
		*p++ = 0x82;
		*p++ = (unsigned char)(len >> 8);
		*p++ = (unsigned char)len;
	} else {
		*p++ = 0x83;
		*p++ = (unsigned char)(len >> 16);
		*p++ = (unsigned char)(len >> 8);
		*p++ = (unsigned char)len;
	}
	return p;
}

/* DER helper: write tag + length, return pointer past written bytes */
static unsigned char *der_put_tag_length(unsigned char *p, unsigned char tag,
					 size_t len)
{
	*p++ = tag;
	return der_put_length(p, len);
}

/* Well-known OIDs in DER encoding (tag + length + value) */

/* 1.2.840.113549.1.7.2 - signedData */
static const unsigned char oid_signed_data[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02
};
/* 1.2.840.113549.1.7.1 - data */
static const unsigned char oid_data[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
};
/* 2.16.840.1.101.3.4.2.10 - sha3-512 (placeholder digest for PQC) */
static const unsigned char oid_sha3_512[] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a
};
/* 1.3.9999.3.6 - falcon512 (OQS experimental) */
static const unsigned char oid_falcon512_bytes[] = {
	0x06, 0x05, 0x2b, 0xce, 0x0f, 0x03, 0x06
};
/* 1.3.9999.3.9 - falcon1024 (OQS experimental) */
static const unsigned char oid_falcon1024_bytes[] = {
	0x06, 0x05, 0x2b, 0xce, 0x0f, 0x03, 0x09
};

/*
 * Determine the FALCON signature algorithm OID based on key type name.
 * Returns pointer to DER-encoded OID (tag+length+value) and its size.
 */
static const unsigned char *pqc_get_sig_oid(const char *pkey_type,
					    size_t *oid_len)
{
	if (strcasestr(pkey_type, "falcon1024") ||
	    strcasestr(pkey_type, "falcon-1024")) {
		*oid_len = sizeof(oid_falcon1024_bytes);
		return oid_falcon1024_bytes;
	}
	/* Default to falcon512 for "falcon512", "falcon", etc. */
	*oid_len = sizeof(oid_falcon512_bytes);
	return oid_falcon512_bytes;
}

/*
 * Build a PKCS#7 SignedData DER structure for a PQC signature.
 *
 * Structure:
 *   ContentInfo {
 *     contentType: signedData (1.2.840.113549.1.7.2)
 *     content: [0] EXPLICIT SignedData {
 *       version: 1
 *       digestAlgorithms: SET { sha3-512}   (placeholder, overridden by kernel)
 *       contentInfo: { data }              (detached - no content)
 *       certificates: [0] IMPLICIT { <cert DER> }
 *       signerInfos: SET { SignerInfo {
 *         version: 1
 *         issuerAndSerialNumber: { issuer, serial }
 *         digestAlgorithm: sha3-512          (placeholder, overridden by kernel)
 *         digestEncryptionAlgorithm: falcon OID  (triggers PQC path)
 *         encryptedDigest: <signature bytes>
 *       }}
 *     }
 *   }
 *
 * The kernel's PKCS#7 parser processes digestAlgorithm first (sets
 * hash_algo="sha3-512"), then digestEncryptionAlgorithm which for FALCON
 * overrides hash_algo=NULL, triggering the PQC verification path where
 * raw module data is passed directly to the FALCON verifier.
 */
static int pqc_build_pkcs7(EVP_PKEY *pkey, X509 *x509, const char *pkey_type,
			   const unsigned char *module_data,
			   size_t module_len, BIO *out)
{
	EVP_MD_CTX *mdctx = NULL;
	unsigned char *sig_buf = NULL;
	size_t sig_len = 0;
	unsigned char *cert_der = NULL;
	int cert_der_len;
	unsigned char *issuer_der = NULL;
	int issuer_der_len;
	unsigned char *serial_der = NULL;
	int serial_der_len;
	const unsigned char *sig_oid;
	size_t sig_oid_len;
	unsigned char *pkcs7_buf = NULL;
	size_t pkcs7_len;
	unsigned char *p;
	int ret = -1;

	/* Determine which FALCON OID to use */
	sig_oid = pqc_get_sig_oid(pkey_type, &sig_oid_len);

	/* Sign the module data using EVP_DigestSign (PQC: NULL digest) */
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		fprintf(stderr, "EVP_MD_CTX_new failed\n");
		goto out;
	}
	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
		fprintf(stderr, "EVP_DigestSignInit failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}
	/* Get signature size */
	if (EVP_DigestSign(mdctx, NULL, &sig_len, module_data,
			   module_len) != 1) {
		fprintf(stderr, "EVP_DigestSign (size) failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}
	sig_buf = malloc(sig_len);
	if (!sig_buf)
		goto out;
	/* Produce the actual signature */
	if (EVP_DigestSign(mdctx, sig_buf, &sig_len, module_data,
			   module_len) != 1) {
		fprintf(stderr, "EVP_DigestSign failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	/* Get DER-encoded certificate */
	cert_der_len = i2d_X509(x509, NULL);
	if (cert_der_len < 0)
		goto out;
	cert_der = malloc(cert_der_len);
	if (!cert_der)
		goto out;
	{
		unsigned char *tmp = cert_der;
		i2d_X509(x509, &tmp);
	}

	/* Get DER-encoded issuer Name */
	issuer_der_len = i2d_X509_NAME(X509_get_issuer_name(x509), NULL);
	if (issuer_der_len < 0)
		goto out;
	issuer_der = malloc(issuer_der_len);
	if (!issuer_der)
		goto out;
	{
		unsigned char *tmp = issuer_der;
		i2d_X509_NAME(X509_get_issuer_name(x509), &tmp);
	}

	/* Get DER-encoded serial number */
	serial_der_len = i2d_ASN1_INTEGER(X509_get_serialNumber(x509), NULL);
	if (serial_der_len < 0)
		goto out;
	serial_der = malloc(serial_der_len);
	if (!serial_der)
		goto out;
	{
		unsigned char *tmp = serial_der;
		i2d_ASN1_INTEGER(X509_get_serialNumber(x509), &tmp);
	}

	/*
	 * Now build the PKCS#7 DER bottom-up, computing sizes first.
	 *
	 * AlgorithmIdentifier for sha3-512(placeholder):
	 *   SEQUENCE { OID sha3-512, NULL }
	 */
	size_t sha3_512_algid_inner = sizeof(oid_sha3_512) + 2; /* OID + NULL(05 00) */
	size_t sha3_512_algid = 1 + der_len_size(sha3_512_algid_inner) +
			      sha3_512_algid_inner;

	/*
	 * AlgorithmIdentifier for FALCON signature:
	 *   SEQUENCE { OID falcon }  (no parameters)
	 */
	size_t falcon_algid_inner = sig_oid_len;
	size_t falcon_algid = 1 + der_len_size(falcon_algid_inner) +
			      falcon_algid_inner;

	/* IssuerAndSerialNumber: SEQUENCE { issuer, serial } */
	size_t issn_inner = issuer_der_len + serial_der_len;
	size_t issn = 1 + der_len_size(issn_inner) + issn_inner;

	/* encryptedDigest: OCTET STRING { sig_buf } */
	size_t enc_digest = 1 + der_len_size(sig_len) + sig_len;

	/* SignerInfo: SEQUENCE { version(3), issn, digestAlgo, sigAlgo, sig } */
	size_t si_inner = 3 + issn + sha3_512_algid + falcon_algid + enc_digest;
	size_t si = 1 + der_len_size(si_inner) + si_inner;

	/* signerInfos: SET { SignerInfo } */
	size_t signer_infos = 1 + der_len_size(si) + si;

	/* digestAlgorithms: SET { sha3_512_algid } */
	size_t digest_algos = 1 + der_len_size(sha3_512_algid) + sha3_512_algid;

	/* contentInfo: SEQUENCE { OID data } (detached, no content) */
	size_t ci_inner = sizeof(oid_data);
	size_t ci = 1 + der_len_size(ci_inner) + ci_inner;

	/* certificates: [0] IMPLICIT { cert_der } */
	size_t certs = 1 + der_len_size(cert_der_len) + cert_der_len;

	/* SignedData: SEQUENCE { version(3), digestAlgos, contentInfo,
	 *                        certificates, signerInfos } */
	size_t sd_inner = 3 + digest_algos + ci + certs + signer_infos;
	size_t sd = 1 + der_len_size(sd_inner) + sd_inner;

	/* content: [0] EXPLICIT { SignedData } */
	size_t content = 1 + der_len_size(sd) + sd;

	/* ContentInfo: SEQUENCE { OID signedData, content } */
	size_t outer_inner = sizeof(oid_signed_data) + content;
	pkcs7_len = 1 + der_len_size(outer_inner) + outer_inner;

	/* Allocate and write */
	pkcs7_buf = malloc(pkcs7_len);
	if (!pkcs7_buf)
		goto out;
	p = pkcs7_buf;

	/* ContentInfo SEQUENCE */
	p = der_put_tag_length(p, 0x30, outer_inner);

	/* OID signedData */
	memcpy(p, oid_signed_data, sizeof(oid_signed_data));
	p += sizeof(oid_signed_data);

	/* [0] EXPLICIT content */
	p = der_put_tag_length(p, 0xa0, sd);

	/* SignedData SEQUENCE */
	p = der_put_tag_length(p, 0x30, sd_inner);

	/* version INTEGER 1 */
	*p++ = 0x02; *p++ = 0x01; *p++ = 0x01;

	/* digestAlgorithms SET */
	p = der_put_tag_length(p, 0x31, sha3_512_algid);
	/* AlgorithmIdentifier SEQUENCE { sha3-512, NULL } */
	p = der_put_tag_length(p, 0x30, sha3_512_algid_inner);
	memcpy(p, oid_sha3_512, sizeof(oid_sha3_512));
	p += sizeof(oid_sha3_512);
	*p++ = 0x05; *p++ = 0x00; /* NULL */

	/* contentInfo SEQUENCE { OID data } */
	p = der_put_tag_length(p, 0x30, ci_inner);
	memcpy(p, oid_data, sizeof(oid_data));
	p += sizeof(oid_data);

	/* certificates [0] IMPLICIT */
	p = der_put_tag_length(p, 0xa0, cert_der_len);
	memcpy(p, cert_der, cert_der_len);
	p += cert_der_len;

	/* signerInfos SET */
	p = der_put_tag_length(p, 0x31, si);

	/* SignerInfo SEQUENCE */
	p = der_put_tag_length(p, 0x30, si_inner);

	/* version INTEGER 1 */
	*p++ = 0x02; *p++ = 0x01; *p++ = 0x01;

	/* IssuerAndSerialNumber SEQUENCE */
	p = der_put_tag_length(p, 0x30, issn_inner);
	memcpy(p, issuer_der, issuer_der_len);
	p += issuer_der_len;
	memcpy(p, serial_der, serial_der_len);
	p += serial_der_len;

	/* digestAlgorithm: SEQUENCE { sha3-512, NULL } (placeholder) */
	p = der_put_tag_length(p, 0x30, sha3_512_algid_inner);
	memcpy(p, oid_sha3_512, sizeof(oid_sha3_512));
	p += sizeof(oid_sha3_512);
	*p++ = 0x05; *p++ = 0x00;

	/* digestEncryptionAlgorithm: SEQUENCE { falcon OID } */
	p = der_put_tag_length(p, 0x30, falcon_algid_inner);
	memcpy(p, sig_oid, sig_oid_len);
	p += sig_oid_len;

	/* encryptedDigest: OCTET STRING */
	p = der_put_tag_length(p, 0x04, sig_len);
	memcpy(p, sig_buf, sig_len);
	p += sig_len;

	/* Sanity check */
	if ((size_t)(p - pkcs7_buf) != pkcs7_len) {
		fprintf(stderr, "PQC PKCS#7: size mismatch %zu != %zu\n",
			(size_t)(p - pkcs7_buf), pkcs7_len);
		goto out;
	}

	/* Write to output BIO */
	if (BIO_write(out, pkcs7_buf, pkcs7_len) != (int)pkcs7_len) {
		fprintf(stderr, "PQC PKCS#7: write failed\n");
		goto out;
	}

	ret = 0;
out:
	free(pkcs7_buf);
	free(serial_der);
	free(issuer_der);
	free(cert_der);
	free(sig_buf);
	EVP_MD_CTX_free(mdctx);
	return ret;
}

#endif /* OPENSSL_VERSION_MAJOR >= 3 */

int main(int argc, char **argv)
{
	struct module_signature sig_info = { .id_type = PKEY_ID_PKCS7 };
	char *hash_algo = NULL;
	char *private_key_name = NULL, *raw_sig_name = NULL;
	char *x509_name, *module_name, *dest_name;
	bool save_sig = false, replace_orig;
	bool sign_only = false;
	bool raw_sig = false;
	bool is_pqc = false;
	const char *pkey_type = NULL;
	unsigned char buf[4096];
	unsigned long module_size, sig_size;
	unsigned int use_signed_attrs;
	const EVP_MD *digest_algo = NULL;
	EVP_PKEY *private_key;
#ifndef USE_PKCS7
	CMS_ContentInfo *cms = NULL;
	unsigned int use_keyid = 0;
#else
	PKCS7 *pkcs7 = NULL;
#endif
	X509 *x509;
	BIO *bd, *bm;
	int opt, n;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	ERR_clear_error();

#if OPENSSL_VERSION_MAJOR >= 3
	/*
	 * Try to load the OQS provider for post-quantum algorithm support
	 * (FALCON, etc.). If not available, fall back to default provider
	 * only - classical algorithms will still work fine.
	 */
	if (OSSL_PROVIDER_try_load(NULL, "oqsprovider", true))
		OSSL_PROVIDER_try_load(NULL, "default", true);
#endif

	key_pass = getenv("KBUILD_SIGN_PIN");

#ifndef USE_PKCS7
	use_signed_attrs = CMS_NOATTR;
#else
	use_signed_attrs = PKCS7_NOATTR;
#endif

	do {
		opt = getopt(argc, argv, "sdpk");
		switch (opt) {
		case 's': raw_sig = true; break;
		case 'p': save_sig = true; break;
		case 'd': sign_only = true; save_sig = true; break;
#ifndef USE_PKCS7
		case 'k': use_keyid = CMS_USE_KEYID; break;
#endif
		case -1: break;
		default: format();
		}
	} while (opt != -1);

	argc -= optind;
	argv += optind;
	if (argc < 4 || argc > 5)
		format();

	if (raw_sig) {
		raw_sig_name = argv[0];
		hash_algo = argv[1];
	} else {
		hash_algo = argv[0];
		private_key_name = argv[1];
	}
	x509_name = argv[2];
	module_name = argv[3];
	if (argc == 5 && strcmp(argv[3], argv[4]) != 0) {
		dest_name = argv[4];
		replace_orig = false;
	} else {
		ERR(asprintf(&dest_name, "%s.~signed~", module_name) < 0,
		    "asprintf");
		replace_orig = true;
	}

#ifdef USE_PKCS7
	if (strcmp(hash_algo, "sha1") != 0) {
		fprintf(stderr, "sign-file: %s only supports SHA1 signing\n",
			OPENSSL_VERSION_TEXT);
		exit(3);
	}
#endif

	/* Open the module file */
	bm = BIO_new_file(module_name, "rb");
	ERR(!bm, "%s", module_name);

	if (!raw_sig) {
		/* Read the private key and the X.509 cert the PKCS#7 message
		 * will point to.
		 */
		private_key = read_private_key(private_key_name);
		x509 = read_x509(x509_name);

#if OPENSSL_VERSION_MAJOR >= 3
		/*
		 * Detect post-quantum key types (FALCON, etc.) provided by
		 * oqs-provider. PQC algorithms handle hashing internally
		 * so no separate digest algorithm is needed for CMS signing.
		 */
		pkey_type = EVP_PKEY_get0_type_name(private_key);
		if (pkey_type &&
		    (strcasestr(pkey_type, "falcon") ||
		     strcasestr(pkey_type, "dilithium") ||
		     strcasestr(pkey_type, "sphincs")))
			is_pqc = true;
#endif

		if (is_pqc) {
#if OPENSSL_VERSION_MAJOR >= 3
			/*
			 * PQC path: bypass OpenSSL CMS (which doesn't support
			 * PQC key NIDs). Use EVP_DigestSign for the raw
			 * signature and manually construct PKCS#7 DER.
			 */
			unsigned char *mod_data;
			size_t mod_len;

			/* Read entire module into memory for signing */
			mod_len = 0;
			{
				unsigned char tmp[65536];
				int r;
				BIO *mem = BIO_new(BIO_s_mem());

				while ((r = BIO_read(bm, tmp, sizeof(tmp))) > 0)
					BIO_write(mem, tmp, r);
				mod_len = BIO_get_mem_data(mem, &mod_data);
				/* mod_data points into mem's buffer */

				/* Open destination, copy module data */
				bd = BIO_new_file(dest_name, "wb");
				ERR(!bd, "%s", dest_name);
				ERR(BIO_write(bd, mod_data, mod_len) !=
				    (int)mod_len,
				    "%s", dest_name);
				module_size = mod_len;

				/* Build and append PKCS#7 */
				BIO *sig_bio = BIO_new(BIO_s_mem());
				ERR(pqc_build_pkcs7(private_key, x509,
						    pkey_type, mod_data,
						    mod_len, sig_bio) != 0,
				    "PQC PKCS#7 construction");

				unsigned char *sig_data;
				long sig_sz = BIO_get_mem_data(sig_bio,
							       &sig_data);
				ERR(BIO_write(bd, sig_data, sig_sz) != sig_sz,
				    "%s", dest_name);
				sig_size = sig_sz;

				if (save_sig) {
					char *sig_file_name;
					BIO *b;

					ERR(asprintf(&sig_file_name, "%s.p7s",
						     module_name) < 0,
					    "asprintf");
					b = BIO_new_file(sig_file_name, "wb");
					ERR(!b, "%s", sig_file_name);
					ERR(BIO_write(b, sig_data,
						      sig_sz) != sig_sz,
					    "%s", sig_file_name);
					BIO_free(b);
				}

				BIO_free(sig_bio);
				BIO_free(mem);
			}

			BIO_free(bm);

			if (sign_only) {
				BIO_free(bd);
				return 0;
			}

			/* Append module_signature struct and magic */
			sig_info.sig_len = htonl(sig_size);
			ERR(BIO_write(bd, &sig_info, sizeof(sig_info)) < 0,
			    "%s", dest_name);
			ERR(BIO_write(bd, magic_number,
				      sizeof(magic_number) - 1) < 0,
			    "%s", dest_name);
			ERR(BIO_free(bd) != 1, "%s", dest_name);

			if (replace_orig)
				ERR(rename(dest_name, module_name) < 0,
				    "%s", dest_name);

			return 0;
#endif
		}

		if (!is_pqc) {
			/* Digest the module data. */
			OpenSSL_add_all_digests();
			drain_openssl_errors(__LINE__, 0);
			digest_algo = EVP_get_digestbyname(hash_algo);
			ERR(!digest_algo, "EVP_get_digestbyname");
		}

#ifndef USE_PKCS7
		/* Load the signature message from the digest buffer. */
		cms = CMS_sign(NULL, NULL, NULL, NULL,
			        CMS_PARTIAL | CMS_BINARY |
			       CMS_DETACHED | CMS_STREAM);
		ERR(!cms, "CMS_sign");

		ERR(!CMS_add1_signer(cms, x509, private_key, digest_algo,
				      CMS_BINARY |
				     CMS_NOSMIMECAP | use_keyid |
				     use_signed_attrs),
		    "CMS_add1_signer");
		ERR(CMS_final(cms, bm, NULL,  CMS_BINARY) != 1,
		    "CMS_final");

#else
		pkcs7 = PKCS7_sign(x509, private_key, NULL, bm,
				    PKCS7_BINARY |
				   PKCS7_DETACHED | use_signed_attrs);
		ERR(!pkcs7, "PKCS7_sign");
#endif

		if (save_sig) {
			char *sig_file_name;
			BIO *b;

			ERR(asprintf(&sig_file_name, "%s.p7s", module_name) < 0,
			    "asprintf");
			b = BIO_new_file(sig_file_name, "wb");
			ERR(!b, "%s", sig_file_name);
#ifndef USE_PKCS7
			ERR(i2d_CMS_bio_stream(b, cms, NULL, 0) != 1,
			    "%s", sig_file_name);
#else
			ERR(i2d_PKCS7_bio(b, pkcs7) != 1,
			    "%s", sig_file_name);
#endif
			BIO_free(b);
		}

		if (sign_only) {
			BIO_free(bm);
			return 0;
		}
	}

	/* Open the destination file now so that we can shovel the module data
	 * across as we read it.
	 */
	bd = BIO_new_file(dest_name, "wb");
	ERR(!bd, "%s", dest_name);

	/* Append the marker and the PKCS#7 message to the destination file */
	ERR(BIO_reset(bm) < 0, "%s", module_name);
	while ((n = BIO_read(bm, buf, sizeof(buf))),
	       n > 0) {
		ERR(BIO_write(bd, buf, n) < 0, "%s", dest_name);
	}
	BIO_free(bm);
	ERR(n < 0, "%s", module_name);
	module_size = BIO_number_written(bd);

	if (!raw_sig) {
#ifndef USE_PKCS7
		ERR(i2d_CMS_bio_stream(bd, cms, NULL, 0) != 1, "%s", dest_name);
#else
		ERR(i2d_PKCS7_bio(bd, pkcs7) != 1, "%s", dest_name);
#endif
	} else {
		BIO *b;

		/* Read the raw signature file and write the data to the
		 * destination file
		 */
		b = BIO_new_file(raw_sig_name, "rb");
		ERR(!b, "%s", raw_sig_name);
		while ((n = BIO_read(b, buf, sizeof(buf))), n > 0)
			ERR(BIO_write(bd, buf, n) < 0, "%s", dest_name);
		BIO_free(b);
	}

	sig_size = BIO_number_written(bd) - module_size;
	sig_info.sig_len = htonl(sig_size);
	ERR(BIO_write(bd, &sig_info, sizeof(sig_info)) < 0, "%s", dest_name);
	ERR(BIO_write(bd, magic_number, sizeof(magic_number) - 1) < 0, "%s", dest_name);

	ERR(BIO_free(bd) != 1, "%s", dest_name);

	/* Finally, if we're signing in place, replace the original. */
	if (replace_orig)
		ERR(rename(dest_name, module_name) < 0, "%s", dest_name);

	return 0;
}
