
// SPDX-License-Identifier: GPL-2.0
/*
 * boot_certs_sysfs (research, strict-ish module-dev)
 *
 * - Reads <boot>/certs/chain.pem once at init
 * - Verifies SHA3-512 hash against kernel cmdline via /proc/cmdline:
 *     boot_certs.sha3=<128 hex chars>
 * - Enforces backing filesystem is read-only (+ optional fstype match)
 * - Parses PEM bundle into individual cert DER blobs; reorders so "root" is at [0]
 *   (root detected as self-issued: subject == issuer, DER-slice compare)
 * - Exposes cert via sysfs bin_attribute:
 *     /sys/kernel/boot_certs/chain.pem
 * - Exposes:
 *     /sys/kernel/boot_certs/ok
 *     /sys/kernel/boot_certs/status
 *     /sys/kernel/boot_certs/sealed (one-way true; calls hook stub)
 *
 * STRICT RESEARCH NOTES
 * - Real X.509 signature chain validation + expiry enforcement requires either:
 *   (a) in-tree use of kernel X.509 parser/verify APIs, or
 *   (b) implementing a full verifier inside this module (large).
 * This module provides:
 *   - safe PEM splitting and basic structural parsing needed for ordering,
 *   - strict RO/fs policy and cmdline hash pinning,
 *   - a sealing sysfs API with a hook stub (EOPNOTSUPP as module).
 */

#include <linux/atomic.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/hex.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kconfig.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/base64.h>

/* Base64 decode API differs across kernel versions; adapt at compile-time. */
static inline int bc_base64_decode(const char *src, int len, u8 *dst)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return base64_decode(src, len, dst);
#else
	return base64_decode(dst, src, len);
#endif
}

/* Maximum total PEM bytes read from disk (compile-time overrideable). */
#ifndef BOOT_CERTS_MAX_BYTES
#define BOOT_CERTS_MAX_BYTES 262144u
#endif

#ifndef BOOT_CERTS_CMDLINE_MAX
#define BOOT_CERTS_CMDLINE_MAX 4096u
#endif

#define BOOT_CERTS_DIRNAME        "boot_certs"
#define BOOT_CERTS_CERT_REL       "certs/chain.pem"

#define BOOT_CERTS_CMDLINE_OPT    "boot_certs.sha3"
#define BOOT_CERTS_DIGEST_NAME    "sha3-512"
#define BOOT_CERTS_DIGEST_LEN     64
#define BOOT_CERTS_DIGEST_HEX     (BOOT_CERTS_DIGEST_LEN * 2)

#if defined(BOOT_CERTS_MOUNT_FIRMWARE)
#define BOOT_CERTS_BOOT_PATH      "/boot/firmware"
#elif defined(BOOT_CERTS_MOUNT_BOOT)
#define BOOT_CERTS_BOOT_PATH      "/boot"
#else
#define BOOT_CERTS_BOOT_PATH      "/boot/firmware"
#endif

#ifndef BOOT_CERTS_SKIP_FSTYPE_CHECK
#ifndef BOOT_CERTS_EXPECT_FSTYPE_STR
#define BOOT_CERTS_EXPECT_FSTYPE_STR "vfat"
#endif
#endif

#define BOOT_CERTS_DEBUG
#ifdef BOOT_CERTS_DEBUG
#define bc_dbg(fmt, ...) pr_info("boot_certs: " fmt, ##__VA_ARGS__)
#else
#define bc_dbg(fmt, ...) do { } while (0)
#endif

enum boot_certs_violation {
	BC_V_NONE = 0,
	BC_V_PATH_LOOKUP,
	BC_V_FS_RW,
	BC_V_FS_TYPE,
	BC_V_FILE_OPEN,
	BC_V_NOT_REGULAR,
	BC_V_FILE_SIZE,
	BC_V_ALLOC,
	BC_V_READ,
	BC_V_CMDLINE,
	BC_V_HASH,
	BC_V_PEM_PARSE,
	BC_V_ASN1_PARSE,
	BC_V_SYSFS,
	BC_V_SEAL,
};

static atomic_t boot_certs_poisoned = ATOMIC_INIT(0);
static bool boot_certs_sha_ok;
static bool boot_certs_sealed;
static enum boot_certs_violation boot_certs_last_violation;
static DEFINE_RATELIMIT_STATE(boot_certs_rs, HZ, 5);

static struct kobject *boot_certs_kobj;

static void *chain_buf;
static size_t chain_len;

/* Parsed certs (DER) extracted from PEM, reordered so root is at [0] */
#define BC_MAX_CERTS 64

struct bc_cert {
	u8    *der;
	size_t der_len;

	/* issuer and subject DER slices (inside TBSCertificate) */
	const u8 *issuer;
	size_t issuer_len;
	const u8 *subject;
	size_t subject_len;
};

static struct bc_cert bc_certs[BC_MAX_CERTS];
static size_t bc_cert_count;

#if IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
int secondary_trusted_keys_seal(void);
#endif
#if IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
int secondary_trusted_keys_add_cert(const void *der, size_t der_len,
				   const char *desc);
#endif


static const char *boot_certs_violation_str(enum boot_certs_violation v)
{
	switch (v) {
	case BC_V_NONE:        return "none";
	case BC_V_PATH_LOOKUP: return "path_lookup";
	case BC_V_FS_RW:       return "filesystem_writable";
	case BC_V_FS_TYPE:     return "filesystem_type_mismatch";
	case BC_V_FILE_OPEN:   return "file_open_failed";
	case BC_V_NOT_REGULAR: return "not_regular_file";
	case BC_V_FILE_SIZE:   return "file_size_invalid";
	case BC_V_ALLOC:       return "alloc_failed";
	case BC_V_READ:        return "file_read_error";
	case BC_V_CMDLINE:     return "cmdline_missing_or_invalid";
	case BC_V_HASH:        return "sha3_mismatch_or_hash_error";
	case BC_V_PEM_PARSE:   return "pem_parse_failed";
	case BC_V_ASN1_PARSE:  return "asn1_min_parse_failed";
	case BC_V_SYSFS:       return "sysfs_create_failed";
	case BC_V_SEAL:        return "seal_failed_or_unsupported";
	default:               return "unknown";
	}
}

static void boot_certs_poison(enum boot_certs_violation why)
{
	boot_certs_last_violation = why;
	atomic_set(&boot_certs_poisoned, 1);
	boot_certs_sha_ok = false;
}



static int boot_certs_secondary_trusted_keys_seal(void)
{
#if IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
	int ret = secondary_trusted_keys_seal();
	if (ret == -EEXIST) /* optional idempotency */
		ret = 0;
	return ret;
#else
	return -EOPNOTSUPP;
#endif
}


static int boot_certs_load_into_secondary_keyring(void)
{
#if !IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
	return -EOPNOTSUPP;
#else
	size_t i;
	int ret;

	if (!boot_certs_sha_ok)
		return -EACCES;

	for (i = 0; i < bc_cert_count; i++) {
		char desc[64];

		/* Stable, readable name. (You can refine later.) */
		snprintf(desc, sizeof(desc), "boot_certs:%zu", i);

		ret = secondary_trusted_keys_add_cert(bc_certs[i].der,
						     bc_certs[i].der_len,
						     desc);
		if (ret < 0) {
			bc_dbg("keyring: add cert idx=%zu failed (err=%d)\n", i, ret);
			return ret;
		}
	}

	return 0;
#endif
}

/* ---------- policy: cert path must sit on RO fs (+ optional fstype) ---------- */

static int boot_certs_check_policy(const char *path_str)
{
	struct path path;
	struct super_block *sb;
	const char *fstype;
	int err;

	if (atomic_read(&boot_certs_poisoned))
		return -EACCES;

	err = kern_path(path_str, LOOKUP_FOLLOW, &path);
	if (err) {
		bc_dbg("policy: kern_path failed for %s (err=%d)\n", path_str, err);
		boot_certs_poison(BC_V_PATH_LOOKUP);
		return -EACCES;
	}

	sb = path.mnt->mnt_sb;
	fstype = (sb->s_type && sb->s_type->name) ? sb->s_type->name : "unknown";

	if (!sb_rdonly(sb)) {
		bc_dbg("policy: backing fs is RW for %s (fstype=%s)\n", path_str, fstype);
		path_put(&path);
		boot_certs_poison(BC_V_FS_RW);
		return -EACCES;
	}

#ifndef BOOT_CERTS_SKIP_FSTYPE_CHECK
	if (strcmp(fstype, BOOT_CERTS_EXPECT_FSTYPE_STR)) {
		bc_dbg("policy: fstype mismatch for %s (got=%s expected=%s)\n",
		       path_str, fstype, BOOT_CERTS_EXPECT_FSTYPE_STR);
		path_put(&path);
		boot_certs_poison(BC_V_FS_TYPE);
		return -EACCES;
	}
#endif

	path_put(&path);
	return 0;
}

/* ---------- file read: read once, bounded, complete ---------- */

static int boot_certs_read_file_once(const char *path)
{
	struct file *f;
	loff_t pos = 0;
	loff_t size;
	void *buf;
	ssize_t n;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		bc_dbg("file: filp_open failed for %s (err=%ld)\n", path, PTR_ERR(f));
		boot_certs_poison(BC_V_FILE_OPEN);
		return (int)PTR_ERR(f);
	}

	if (!S_ISREG(file_inode(f)->i_mode)) {
		bc_dbg("file: not a regular file: %s\n", path);
		filp_close(f, NULL);
		boot_certs_poison(BC_V_NOT_REGULAR);
		return -EINVAL;
	}

	size = i_size_read(file_inode(f));
	if (size <= 0 || size > (loff_t)BOOT_CERTS_MAX_BYTES) {
		bc_dbg("file: invalid size for %s: %lld (max=%u)\n",
		       path, (long long)size, BOOT_CERTS_MAX_BYTES);
		filp_close(f, NULL);
		boot_certs_poison(BC_V_FILE_SIZE);
		return -EFBIG;
	}

	buf = kvmalloc((size_t)size, GFP_KERNEL);
	if (!buf) {
		bc_dbg("file: alloc failed (%lld bytes)\n", (long long)size);
		filp_close(f, NULL);
		boot_certs_poison(BC_V_ALLOC);
		return -ENOMEM;
	}

	n = kernel_read(f, buf, (size_t)size, &pos);
	filp_close(f, NULL);

	if (n < 0) {
		bc_dbg("file: kernel_read failed for %s (err=%zd)\n", path, n);
		kvfree(buf);
		boot_certs_poison(BC_V_READ);
		return (int)n;
	}

	if (n != size) {
		bc_dbg("file: short read for %s (got=%zd expected=%lld)\n",
		       path, n, (long long)size);
		kvfree(buf);
		boot_certs_poison(BC_V_READ);
		return -EIO;
	}

	chain_buf = buf;
	chain_len = (size_t)size;
	return 0;
}

/* ---------- cmdline read via /proc/cmdline ---------- */

static int boot_certs_read_cmdline(char **out_buf)
{
	struct file *f;
	char *buf;
	ssize_t n;
	loff_t pos = 0;

	*out_buf = NULL;

	f = filp_open("/proc/cmdline", O_RDONLY, 0);
	if (IS_ERR(f)) {
		bc_dbg("cmdline: cannot open /proc/cmdline (err=%ld)\n", PTR_ERR(f));
		return (int)PTR_ERR(f);
	}

	buf = kmalloc(BOOT_CERTS_CMDLINE_MAX + 1, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return -ENOMEM;
	}

	n = kernel_read(f, buf, BOOT_CERTS_CMDLINE_MAX, &pos);
	filp_close(f, NULL);

	if (n < 0) {
		bc_dbg("cmdline: kernel_read failed (err=%zd)\n", n);
		kfree(buf);
		return (int)n;
	}

	buf[n] = '\0';
	*out_buf = buf;
	return 0;
}

static void boot_certs_free_cmdline(char *buf)
{
	kfree(buf);
}

static int boot_certs_get_expected_digest(u8 out[BOOT_CERTS_DIGEST_LEN])
{
	char *cmdline = NULL;
	const char *p;
	char hex[BOOT_CERTS_DIGEST_HEX + 1];
	size_t i;
	int ret;

	ret = boot_certs_read_cmdline(&cmdline);
	if (ret) {
		boot_certs_poison(BC_V_CMDLINE);
		return ret;
	}

	p = cmdline;
	while ((p = strstr(p, BOOT_CERTS_CMDLINE_OPT "=")) != NULL) {
		if (p == cmdline || p[-1] == ' ') {
			p += strlen(BOOT_CERTS_CMDLINE_OPT "=");
			break;
		}
		p++;
	}
	if (!p) {
		bc_dbg("cmdline: missing %s=\n", BOOT_CERTS_CMDLINE_OPT);
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < BOOT_CERTS_DIGEST_HEX; i++) {
		if (!isxdigit(p[i])) {
			bc_dbg("cmdline: non-hex at pos %zu\n", i);
			ret = -EINVAL;
			goto out;
		}
		hex[i] = p[i];
	}
	hex[BOOT_CERTS_DIGEST_HEX] = '\0';

	if (p[BOOT_CERTS_DIGEST_HEX] != '\0' &&
	    p[BOOT_CERTS_DIGEST_HEX] != ' '  &&
	    p[BOOT_CERTS_DIGEST_HEX] != '\n') {
		bc_dbg("cmdline: digest not terminated at boundary\n");
		ret = -EINVAL;
		goto out;
	}

	if (hex2bin(out, hex, BOOT_CERTS_DIGEST_LEN)) {
		bc_dbg("cmdline: hex2bin failed\n");
		ret = -EINVAL;
		goto out;
	}

	ret = 0;

out:
	boot_certs_free_cmdline(cmdline);
	if (ret)
		boot_certs_poison(BC_V_CMDLINE);
	return ret;
}

/* ---------- SHA3-512 using shash ---------- */

static int boot_certs_sha3_512(const void *data, size_t len,
			       u8 out[BOOT_CERTS_DIGEST_LEN])
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	tfm = crypto_alloc_shash(BOOT_CERTS_DIGEST_NAME, 0, 0);
	if (IS_ERR(tfm)) {
		bc_dbg("crypto: alloc %s failed (err=%ld)\n",
		       BOOT_CERTS_DIGEST_NAME, PTR_ERR(tfm));
		return (int)PTR_ERR(tfm);
	}

	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_free_desc;
	ret = crypto_shash_update(desc, data, len);
	if (ret)
		goto out_free_desc;
	ret = crypto_shash_final(desc, out);

out_free_desc:
	kfree(desc);
out_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/* ---------- minimal ASN.1 TLV reader for DER ---------- */

struct bc_asn1 {
	const u8 *p;
	const u8 *end;
};

static int bc_asn1_get_tag_len(struct bc_asn1 *a, u8 *tag, size_t *len, const u8 **val)
{
	size_t l = 0;
	u8 t;
	const u8 *p;

	if (a->p >= a->end)
		return -EINVAL;

	p = a->p;
	t = *p++;

	if (p >= a->end)
		return -EINVAL;

	/* length */
	if ((*p & 0x80) == 0) {
		l = *p++;
	} else {
		u8 n = *p++ & 0x7f;
		size_t i;

		if (n == 0 || n > sizeof(size_t))
			return -EINVAL;
		if ((size_t)(a->end - p) < n)
			return -EINVAL;

		l = 0;
		for (i = 0; i < n; i++) {
			l = (l << 8) | p[i];
		}
		p += n;
	}

	if ((size_t)(a->end - p) < l)
		return -EINVAL;

	*tag = t;
	*len = l;
	*val = p;

	/* advance */
	a->p = p + l;
	return 0;
}

/*
 * Parse issuer+subject DER slices:
 * Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }
 * TBSCertificate ::= SEQUENCE {
 *   version [0] EXPLICIT ... OPTIONAL,
 *   serialNumber INTEGER,
 *   signature AlgorithmIdentifier,
 *   issuer Name,
 *   validity Validity,
 *   subject Name,
 *   ...
 * }
 *
 * We only need issuer and subject as raw DER slices for equality comparisons.
 */
static int bc_x509_extract_issuer_subject(struct bc_cert *c)
{
	struct bc_asn1 a, cert_seq, tbs_seq;
	u8 tag;
	size_t len;
	const u8 *val;

	memset(&a, 0, sizeof(a));
	a.p = c->der;
	a.end = c->der + c->der_len;

	/* Certificate SEQUENCE */
	cert_seq = a;
	if (bc_asn1_get_tag_len(&cert_seq, &tag, &len, &val))
		return -EINVAL;
	if (tag != 0x30) /* SEQUENCE */
		return -EINVAL;

	/* val..val+len is Certificate contents */
	tbs_seq.p = val;
	tbs_seq.end = val + len;

	/* tbsCertificate SEQUENCE */
	if (bc_asn1_get_tag_len(&tbs_seq, &tag, &len, &val))
		return -EINVAL;
	if (tag != 0x30)
		return -EINVAL;

	/* Now parse inside TBSCertificate */
	{
		struct bc_asn1 t;
		const u8 *tbs_start = val;
		const u8 *tbs_end = val + len;

		t.p = tbs_start;
		t.end = tbs_end;

		/* Optional version [0] EXPLICIT => tag A0 */
		if (t.p < t.end && *t.p == 0xA0) {
			if (bc_asn1_get_tag_len(&t, &tag, &len, &val))
				return -EINVAL;
			/* ignore */
		}

		/* serialNumber INTEGER */
		if (bc_asn1_get_tag_len(&t, &tag, &len, &val))
			return -EINVAL;
		if (tag != 0x02)
			return -EINVAL;

		/* signature AlgorithmIdentifier (SEQUENCE) */
		if (bc_asn1_get_tag_len(&t, &tag, &len, &val))
			return -EINVAL;
		if (tag != 0x30)
			return -EINVAL;

		/* issuer Name (SEQUENCE) */
		{
			const u8 *issuer_tlv = t.p; /* current cursor is after algo, before issuer TLV */
			struct bc_asn1 tmp = t;
			const u8 *issuer_val;
			size_t issuer_len;
			u8 issuer_tag;

			/* peek issuer TLV by decoding again using tmp */
			if (bc_asn1_get_tag_len(&tmp, &issuer_tag, &issuer_len, &issuer_val))
				return -EINVAL;
			if (issuer_tag != 0x30)
				return -EINVAL;

			/* issuer TLV start = issuer_tlv; total = (tmp.p - issuer_tlv) */
			c->issuer = issuer_tlv;
			c->issuer_len = (size_t)(tmp.p - issuer_tlv);

			/* advance real cursor */
			t = tmp;
		}

		/* validity (SEQUENCE) */
		if (bc_asn1_get_tag_len(&t, &tag, &len, &val))
			return -EINVAL;
		if (tag != 0x30)
			return -EINVAL;

		/* subject Name (SEQUENCE) */
		{
			const u8 *subject_tlv = t.p;
			struct bc_asn1 tmp = t;
			const u8 *subject_val;
			size_t subject_len;
			u8 subject_tag;

			if (bc_asn1_get_tag_len(&tmp, &subject_tag, &subject_len, &subject_val))
				return -EINVAL;
			if (subject_tag != 0x30)
				return -EINVAL;

			c->subject = subject_tlv;
			c->subject_len = (size_t)(tmp.p - subject_tlv);

			/* advance */
			t = tmp;
		}
	}

	if (!c->issuer || !c->subject || !c->issuer_len || !c->subject_len)
		return -EINVAL;

	return 0;
}

/* ---------- PEM parsing + base64 decode ---------- */

static const char bc_pem_begin[] = "-----BEGIN CERTIFICATE-----";
static const char bc_pem_end[]   = "-----END CERTIFICATE-----";

static bool bc_is_b64_char(char c)
{
	if ((c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '+' || c == '/' || c == '=')
		return true;
	return false;
}

static int bc_pem_extract_all(const u8 *pem, size_t pem_len)
{
	const char *s = (const char *)pem;
	const char *e = (const char *)pem + pem_len;
	size_t count = 0;

	memset(bc_certs, 0, sizeof(bc_certs));
	bc_cert_count = 0;

	while (1) {
		const char *b, *x, *end;
		size_t b64_raw_len, b64_clean_len, der_max;
		char *b64_clean;
		u8 *der;
		int der_len;

		b = strnstr(s, bc_pem_begin, e - s);
		if (!b)
			break;

		x = b + strlen(bc_pem_begin);
		while (x < e && (*x == '\r' || *x == '\n' || *x == ' ' || *x == '\t'))
			x++;

		end = strnstr(x, bc_pem_end, e - x);
		if (!end)
			return -EINVAL;

		/* trim trailing whitespace before END marker */
		while (end > x && (end[-1] == '\r' || end[-1] == '\n' ||
				   end[-1] == ' '  || end[-1] == '\t'))
			end--;

		b64_raw_len = (size_t)(end - x);
		if (b64_raw_len == 0)
			return -EINVAL;

		if (count >= BC_MAX_CERTS)
			return -E2BIG;

		/* 1) Clean base64: drop whitespace, reject other garbage */
		b64_clean = kmalloc(b64_raw_len + 1, GFP_KERNEL);
		if (!b64_clean)
			return -ENOMEM;

		b64_clean_len = 0;
		for (size_t i = 0; i < b64_raw_len; i++) {
			char c = x[i];

			if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
				continue;

			if (!bc_is_b64_char(c)) {
#ifdef BOOT_CERTS_DEBUG
				pr_info("boot_certs: pem: bad base64 char 0x%02x at cert=%zu offset=%zu\n",
					(unsigned char)c, count, i);
#endif
				kfree(b64_clean);
				return -EINVAL;
			}

			b64_clean[b64_clean_len++] = c;
		}
		b64_clean[b64_clean_len] = '\0';

		/*
		 * 2) Allocate worst-case DER size for base64.
		 * For base64, decoded size <= (n/4)*3, with some slack.
		 */
		if (b64_clean_len < 8) {
#ifdef BOOT_CERTS_DEBUG
			pr_info("boot_certs: pem: base64 too short after clean (cert=%zu raw=%zu clean=%zu)\n",
				count, b64_raw_len, b64_clean_len);
#endif
			kfree(b64_clean);
			return -EINVAL;
		}

		der_max = ((b64_clean_len + 3) / 4) * 3;
		if (der_max == 0 || der_max > BOOT_CERTS_MAX_BYTES) {
#ifdef BOOT_CERTS_DEBUG
			pr_info("boot_certs: pem: der_max invalid (cert=%zu der_max=%zu clean=%zu)\n",
				count, der_max, b64_clean_len);
#endif
			kfree(b64_clean);
			return -EINVAL;
		}

		der = kmalloc(der_max, GFP_KERNEL);
		if (!der) {
			kfree(b64_clean);
			return -ENOMEM;
		}

		der_len = bc_base64_decode(b64_clean, (int)b64_clean_len, der);
		if (der_len <= 0) {
#ifdef BOOT_CERTS_DEBUG
			/* Print a short prefix to help diagnose wrapping/format issues */
			pr_info("boot_certs: pem: base64_decode failed (err=%d) cert=%zu raw=%zu clean=%zu prefix='%.32s'\n",
				der_len, count, b64_raw_len, b64_clean_len, b64_clean);
#endif
			kfree(b64_clean);
			kfree(der);
			return -EINVAL;
		}

		kfree(b64_clean);

		bc_certs[count].der = der;
		bc_certs[count].der_len = (size_t)der_len;

		if (bc_x509_extract_issuer_subject(&bc_certs[count])) {
#ifdef BOOT_CERTS_DEBUG
			pr_info("boot_certs: pem: issuer/subject parse failed cert=%zu der_len=%d\n",
				count, der_len);
#endif
			kfree(der);
			bc_certs[count].der = NULL;
			bc_certs[count].der_len = 0;
			return -EINVAL;
		}

#ifdef BOOT_CERTS_DEBUG
		pr_info("boot_certs: pem: extracted cert=%zu der_len=%d\n", count, der_len);
#endif

		count++;
		s = end + strlen(bc_pem_end);
	}

	if (count == 0)
		return -EINVAL;

	bc_cert_count = count;
	return 0;
}

static void bc_pem_free_all(void)
{
	size_t i;

	for (i = 0; i < bc_cert_count; i++) {
		kfree(bc_certs[i].der);
		memset(&bc_certs[i], 0, sizeof(bc_certs[i]));
	}
	bc_cert_count = 0;
}

/*
 * Reorder certs so that a "root" ends up at index 0.
 * Root detection: issuer DER slice == subject DER slice (self-issued).
 *
 * If multiple self-issued certs exist, pick the first encountered.
 * If none exist, leave order as-is (still exported, hash pinning holds).
 */
static void bc_reorder_root_first(void)
{
	size_t i;
	size_t root = (size_t)-1;
	struct bc_cert tmp;

	for (i = 0; i < bc_cert_count; i++) {
		if (bc_certs[i].issuer_len == bc_certs[i].subject_len &&
		    memcmp(bc_certs[i].issuer, bc_certs[i].subject, bc_certs[i].issuer_len) == 0) {
			root = i;
			break;
		}
	}

	if (root == (size_t)-1 || root == 0)
		return;

	tmp = bc_certs[0];
	bc_certs[0] = bc_certs[root];
	bc_certs[root] = tmp;

	bc_dbg("pem: reordered root cert from idx=%zu to idx=0\n", root);
}

/* ---------- sysfs: chain.pem ---------- */

static ssize_t chain_read(struct file *f, struct kobject *kobj,
			  struct bin_attribute *attr,
			  char *buf, loff_t off, size_t cnt)
{
	char path[sizeof(BOOT_CERTS_BOOT_PATH) + 1 + sizeof(BOOT_CERTS_CERT_REL)];
	size_t avail;

	snprintf(path, sizeof(path), "%s/%s", BOOT_CERTS_BOOT_PATH, BOOT_CERTS_CERT_REL);

	if (boot_certs_check_policy(path))
		return -EACCES;

	if (!boot_certs_sha_ok)
		return -EACCES;

	if (!chain_buf || !chain_len)
		return -ENODATA;

	if (off < 0)
		return -EINVAL;

	if ((size_t)off >= chain_len)
		return 0;

	avail = chain_len - (size_t)off;
	if (cnt > avail)
		cnt = avail;

	memcpy(buf, (u8 *)chain_buf + off, cnt);
	return (ssize_t)cnt;
}

static struct bin_attribute chain_attr = {
	.attr = {
		.name = "chain.pem",
		.mode = 0444,
	},
	.read = chain_read,
	.write = NULL,
	.size = 0,
};

/* ---------- sysfs: ok/status/sealed ---------- */

static ssize_t ok_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	return scnprintf(b, PAGE_SIZE, "%s\n", boot_certs_sha_ok ? "true" : "false");
}
static struct kobj_attribute ok_attr = __ATTR_RO(ok);

static ssize_t sealed_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	return scnprintf(b, PAGE_SIZE, "%s\n", boot_certs_sealed ? "true" : "false");
}

#if IS_ENABLED(CONFIG_BOOT_CERTS_ALLOW_SYSFS_SEAL)
static ssize_t sealed_store(struct kobject *k, struct kobj_attribute *a,
			    const char *buf, size_t count)
{
	bool v;
	int ret;

	if (sysfs_streq(buf, "1") || sysfs_streq(buf, "true"))
		v = true;
	else if (sysfs_streq(buf, "0") || sysfs_streq(buf, "false"))
		return -EINVAL; /* cannot unseal */
	else
		return -EINVAL;

	if (!v)
		return -EINVAL;

	if (!boot_certs_sha_ok)
		return -EACCES;

	if (boot_certs_sealed)
		return count;

	ret = boot_certs_secondary_trusted_keys_seal();
	if (ret) {
		bc_dbg("seal: failed/unsupported (err=%d)\n", ret);
		boot_certs_poison(BC_V_SEAL);
		return ret;
	}

	boot_certs_sealed = true;
	return count;
}

static struct kobj_attribute sealed_attr =
	__ATTR(sealed, 0644, sealed_show, sealed_store);
#else
static struct kobj_attribute sealed_attr = __ATTR_RO(sealed);
#endif

static ssize_t status_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	return scnprintf(b, PAGE_SIZE,
			 "poisoned=%d sha_ok=%d sealed=%d violation=%s size=%zu max=%u certs=%zu algo=%s boot=%s\n",
			 atomic_read(&boot_certs_poisoned),
			 boot_certs_sha_ok,
			 boot_certs_sealed,
			 boot_certs_violation_str(boot_certs_last_violation),
			 chain_len,
			 (unsigned)BOOT_CERTS_MAX_BYTES,
			 bc_cert_count,
			 BOOT_CERTS_DIGEST_NAME,
			 BOOT_CERTS_BOOT_PATH);
}
static struct kobj_attribute status_attr = __ATTR_RO(status);

static struct attribute *attrs[] = {
	&ok_attr.attr,
	&sealed_attr.attr,
	&status_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attrs,
};

/* ---------- init / exit ---------- */

static int __init boot_certs_init(void)
{
	char path[sizeof(BOOT_CERTS_BOOT_PATH) + 1 + sizeof(BOOT_CERTS_CERT_REL)];
	u8 expected[BOOT_CERTS_DIGEST_LEN];
	u8 actual[BOOT_CERTS_DIGEST_LEN];
	int ret;

	boot_certs_sha_ok = false;
	boot_certs_sealed = false;
	boot_certs_last_violation = BC_V_NONE;

	snprintf(path, sizeof(path), "%s/%s", BOOT_CERTS_BOOT_PATH, BOOT_CERTS_CERT_REL);

	ret = boot_certs_check_policy(path);
	if (ret)
		goto out_fail;

	ret = boot_certs_read_file_once(path);
	if (ret)
		goto out_fail;

	/* Parse PEM and reorder so root is at [0] (for future strict chain logic). */
	ret = bc_pem_extract_all((const u8 *)chain_buf, chain_len);
	if (ret) {
		bc_dbg("pem: extract failed (err=%d)\n", ret);
		boot_certs_poison(BC_V_PEM_PARSE);
		goto out_fail;
	}
	bc_reorder_root_first();

	ret = boot_certs_get_expected_digest(expected);
	if (ret)
		goto out_fail;

	ret = boot_certs_sha3_512(chain_buf, chain_len, actual);
	if (ret) {
		bc_dbg("hash: sha3 computation failed (err=%d)\n", ret);
		boot_certs_poison(BC_V_HASH);
		goto out_fail;
	}

	if (memcmp(expected, actual, BOOT_CERTS_DIGEST_LEN)) {
		bc_dbg("hash: mismatch\n");
		boot_certs_poison(BC_V_HASH);
		goto out_fail;
	}

	boot_certs_sha_ok = true;


	ret = boot_certs_load_into_secondary_keyring();
	if (ret) {
		bc_dbg("keyring: load failed (err=%d)\n", ret);
		boot_certs_poison(BC_V_SEAL); /* or a new violation like BC_V_KEYRING */
		goto out_fail;
	}

	boot_certs_kobj = kobject_create_and_add(BOOT_CERTS_DIRNAME, kernel_kobj);
	if (!boot_certs_kobj) {
		boot_certs_poison(BC_V_SYSFS);
		ret = -ENOMEM;
		goto out_fail;
	}

	ret = sysfs_create_group(boot_certs_kobj, &attr_group);
	if (ret) {
		boot_certs_poison(BC_V_SYSFS);
		goto out_kobj;
	}

	chain_attr.size = chain_len;
	ret = sysfs_create_bin_file(boot_certs_kobj, &chain_attr);
	if (ret) {
		boot_certs_poison(BC_V_SYSFS);
		goto out_group;
	}

#if IS_ENABLED(CONFIG_BOOT_CERTS_SEAL_AT_BOOT)
	ret = boot_certs_secondary_trusted_keys_seal();
	if (ret) {
		/*
		 * Module-dev stub returns -EOPNOTSUPP.
		 * For now we fail init to keep strict semantics around "sealed".
		 * If you want dev-mode success, change this to WARN and continue.
		 */
		bc_dbg("seal: failed/unsupported (err=%d)\n", ret);
		boot_certs_poison(BC_V_SEAL);
		goto out_bin;
	}
	boot_certs_sealed = true;
#endif

	pr_info("boot_certs: OK, exported %zu bytes at /sys/kernel/%s/chain.pem\n",
		chain_len, BOOT_CERTS_DIRNAME);
	return 0;

out_bin:
	sysfs_remove_bin_file(boot_certs_kobj, &chain_attr);
out_group:
	sysfs_remove_group(boot_certs_kobj, &attr_group);
out_kobj:
	kobject_put(boot_certs_kobj);
	boot_certs_kobj = NULL;
out_fail:
	if (atomic_read(&boot_certs_poisoned) && __ratelimit(&boot_certs_rs))
		pr_warn("boot_certs: failed: violation=%s\n",
			boot_certs_violation_str(boot_certs_last_violation));

	bc_pem_free_all();
	kvfree(chain_buf);
	chain_buf = NULL;
	chain_len = 0;
	return -EKEYREJECTED;
}

static void __exit boot_certs_exit(void)
{
	if (boot_certs_kobj) {
		sysfs_remove_bin_file(boot_certs_kobj, &chain_attr);
		sysfs_remove_group(boot_certs_kobj, &attr_group);
		kobject_put(boot_certs_kobj);
		boot_certs_kobj = NULL;
	}

	bc_pem_free_all();
	kvfree(chain_buf);
	chain_buf = NULL;
	chain_len = 0;
}

module_init(boot_certs_init);
module_exit(boot_certs_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Boot cert export via sysfs with RO + SHA3-512 verification (+ PEM parse + sealing hook)");