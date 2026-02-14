/* SPDX-License-Identifier: GPL-2.0 */
/*
 * boot_certs_crl.h - Certificate Revocation List support for boot_certs PKI
 *
 * Defines the binary CRL payload format transported inside PKCS#7 signed-data.
 *
 * CRL binary payload format:
 *
 * Header (20 bytes):
 *   [0..3]   magic:     0x43524C31 ("CRL1") big-endian
 *   [4..7]   version:   uint32_be = 1
 *   [8..15]  timestamp: int64_be (seconds since epoch, replay protection)
 *   [16..19] count:     uint32_be (number of revocation entries)
 *
 * Each entry (variable length):
 *   [0..1]   serial_len:  uint16_be (1..20)
 *   [2..]    serial:      raw serial number bytes
 *   [..]     issuer_len:  uint16_be (1..512)
 *   [..]     issuer:      raw DER-encoded issuer Name
 *
 * Matching uses asymmetric_key_generate_id(serial, issuer) which is
 * identical to how x509_cert_parser builds key id[0].
 */
#ifndef _BOOT_CERTS_CRL_H
#define _BOOT_CERTS_CRL_H

#include <linux/types.h>

#define CRL_MAGIC		0x43524C31	/* "CRL1" big-endian */
#define CRL_VERSION		1
#define CRL_HEADER_SIZE		20
#define CRL_MAX_SERIAL_LEN	20
#define CRL_MAX_ISSUER_LEN	512
#define CRL_MAX_ENTRIES		1024
#define CRL_MAX_BLOB_SIZE	(256 * 1024)	/* 256 KiB max PKCS#7 blob */

struct crl_header {
	__be32	magic;
	__be32	version;
	__be64	timestamp;
	__be32	count;
} __packed;

#endif /* _BOOT_CERTS_CRL_H */
