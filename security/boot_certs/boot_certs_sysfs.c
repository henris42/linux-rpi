
// SPDX-License-Identifier: GPL-2.0
/*
 * boot_certs_sysfs - Built-in boot certificate validation with hierarchical sealing
 *
 * IMPORTANT: This is built into the kernel (not a module) to ensure certificate
 * validation occurs before third-party modules are loaded.
 *
 * Features:
 * - Reads <boot>/certs/chain.pem at late_initcall (after filesystem init)
 * - Verifies SHA3-512 hash against kernel cmdline: boot_certs.sha3=<128 hex chars>
 * - Enforces backing filesystem is read-only (+ optional fstype match)
 * - Parses PEM bundle into individual cert DER blobs; reorders so root is at [0]
 *   (root detected as self-signed: subject == issuer, DER-slice compare)
 * - Hierarchical keyring sealing:
 *   - .boot_root_certs: Immutable root CAs (sealed completely)
 *   - .secondary_trusted_keys: All certs, accepts root-signed intermediates
 * - Certificate expiry enforcement with three policies: WARN, REJECT, STRICT
 * - Periodic automated expiry checking via workqueue
 * - Exposes sysfs interface:
 *     /sys/kernel/boot_certs/chain.pem       (RO - certificate chain)
 *     /sys/kernel/boot_certs/ok              (RO - validation status)
 *     /sys/kernel/boot_certs/status          (RO - detailed status)
 *     /sys/kernel/boot_certs/sealed          (RW - one-way sealing trigger)
 *     /sys/kernel/boot_certs/expiry_status   (RO - expiry information)
 *     /sys/kernel/boot_certs/expiry_check_now (WO - manual expiry check)
 *
 * Boot timing:
 * - Runs at late_initcall: after rootfs_initcall, before device_initcall
 * - Requires boot partition mounted (handled by initramfs/early userspace)
 * - Certificates loaded and keyrings sealed before module loading begins
 *
 * Future: Will migrate to secure element (TPM/SE) storage instead of filesystem.
 */

#include <linux/async.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/hex.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kconfig.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/overflow.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/version.h>
#include <linux/base64.h>
#include <linux/timekeeping.h>
#include <linux/workqueue.h>

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
#define BOOT_CERTS_CERT_REL       "chain.pem"

#define BOOT_CERTS_CMDLINE_OPT    "boot_certs.sha3"
#define BOOT_CERTS_DIGEST_NAME    "sha3-512"
#define BOOT_CERTS_DIGEST_LEN     64
#define BOOT_CERTS_DIGEST_HEX     (BOOT_CERTS_DIGEST_LEN * 2)

/*
 * Filesystem paths (fallback when U-Boot memory address not provided):
 * - /boot/firmware/certs (default for Raspberry Pi)
 * - /boot/certs (alternative)
 *
 * Production will use U-Boot FIT image with boot_certs.addr/len parameters.
 */
#if defined(BOOT_CERTS_MOUNT_FIRMWARE)
#define BOOT_CERTS_BOOT_PATH      "/boot/firmware/certs"
#elif defined(BOOT_CERTS_MOUNT_BOOT)
#define BOOT_CERTS_BOOT_PATH      "/boot/certs"
#else
#define BOOT_CERTS_BOOT_PATH      "/boot/firmware/certs"  /* Default: Raspberry Pi */
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
	BC_V_CERT_EXPIRED,
	BC_V_CERT_EXPIRING_SOON,
};

/* Certificate expiry policy (compile-time via Kconfig) */
enum boot_certs_expiry_policy {
	BC_EXPIRY_WARN,      /* Log warning only */
	BC_EXPIRY_REJECT,    /* Reject expired certs */
	BC_EXPIRY_STRICT,    /* Reject certs expiring within grace period */
};

#if defined(CONFIG_BOOT_CERTS_EXPIRY_WARN)
#define BOOT_CERTS_EXPIRY_POLICY BC_EXPIRY_WARN
#elif defined(CONFIG_BOOT_CERTS_EXPIRY_REJECT)
#define BOOT_CERTS_EXPIRY_POLICY BC_EXPIRY_REJECT
#elif defined(CONFIG_BOOT_CERTS_EXPIRY_STRICT)
#define BOOT_CERTS_EXPIRY_POLICY BC_EXPIRY_STRICT
#else
#define BOOT_CERTS_EXPIRY_POLICY BC_EXPIRY_WARN
#endif

#ifdef CONFIG_BOOT_CERTS_EXPIRY_GRACE_DAYS
#define BOOT_CERTS_GRACE_DAYS CONFIG_BOOT_CERTS_EXPIRY_GRACE_DAYS
#else
#define BOOT_CERTS_GRACE_DAYS 30
#endif

#ifdef CONFIG_BOOT_CERTS_EXPIRY_CHECK_INTERVAL
#define BOOT_CERTS_CHECK_INTERVAL_HOURS CONFIG_BOOT_CERTS_EXPIRY_CHECK_INTERVAL
#else
#define BOOT_CERTS_CHECK_INTERVAL_HOURS 24
#endif

/* Expiry tracking */
struct bc_expiry_status {
	int expired_count;
	int expiring_soon_count;
	time64_t last_check;
	time64_t earliest_expiry;  /* Earliest expiry time among all certs */
};

static atomic_t boot_certs_poisoned = ATOMIC_INIT(0);
static bool boot_certs_sha_ok;
static bool boot_certs_sealed;
static enum boot_certs_violation boot_certs_last_violation;
static DEFINE_RATELIMIT_STATE(boot_certs_rs, HZ, 5);

static struct bc_expiry_status expiry_status;
static struct delayed_work expiry_check_work;
static bool expiry_check_enabled;

/* U-Boot memory address parameters (alternative to filesystem) */
static unsigned long boot_certs_addr;
static unsigned long boot_certs_len;

/* Mount-wait retry for /boot/firmware - systemd mounts at ~39s after boot */
#define BOOT_CERTS_MOUNT_WAIT_MS 1000  /* Check every second */
#define BOOT_CERTS_MOUNT_TIMEOUT_MS 300000  /* 5 minutes max wait */

/*
 * Protects all module state including chain_buf, bc_certs, and flags.
 * Locking rules:
 * - Init: No locking needed (single-threaded, before sysfs exposure)
 * - Sysfs ops: Must hold mutex for duration of operation
 * - Exit: Remove sysfs first (blocks until ops complete), then free under mutex
 * - boot_certs_poisoned: Uses atomic ops, can be read without mutex
 */
static DEFINE_MUTEX(boot_certs_mutex);

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

	/* validity period */
	time64_t valid_from;
	time64_t valid_to;
};

static struct bc_cert bc_certs[BC_MAX_CERTS];
static size_t bc_cert_count;

#if IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
int secondary_trusted_keys_seal(void);
int secondary_trusted_keys_add_cert(const void *der, size_t der_len,
				   const char *desc);
int boot_root_certs_add_cert(const void *der, size_t der_len,
			     const char *desc);
#endif


static const char *boot_certs_violation_str(enum boot_certs_violation v)
{
	switch (v) {
	case BC_V_NONE:              return "none";
	case BC_V_PATH_LOOKUP:       return "path_lookup";
	case BC_V_FS_RW:             return "filesystem_writable";
	case BC_V_FS_TYPE:           return "filesystem_type_mismatch";
	case BC_V_FILE_OPEN:         return "file_open_failed";
	case BC_V_NOT_REGULAR:       return "not_regular_file";
	case BC_V_FILE_SIZE:         return "file_size_invalid";
	case BC_V_ALLOC:             return "alloc_failed";
	case BC_V_READ:              return "file_read_error";
	case BC_V_CMDLINE:           return "cmdline_missing_or_invalid";
	case BC_V_HASH:              return "sha3_mismatch_or_hash_error";
	case BC_V_PEM_PARSE:         return "pem_parse_failed";
	case BC_V_ASN1_PARSE:        return "asn1_min_parse_failed";
	case BC_V_SYSFS:             return "sysfs_create_failed";
	case BC_V_SEAL:              return "seal_failed_or_unsupported";
	case BC_V_CERT_EXPIRED:      return "certificate_expired";
	case BC_V_CERT_EXPIRING_SOON: return "certificate_expiring_soon";
	default:                     return "unknown";
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


/*
 * Determine if a certificate is a root CA (self-signed).
 * Root CA detection: subject DER == issuer DER.
 */
static bool bc_is_root_ca(size_t idx)
{
	struct bc_cert *c = &bc_certs[idx];

	if (!c->issuer || !c->subject)
		return false;

	return (c->issuer_len == c->subject_len &&
		memcmp(c->issuer, c->subject, c->issuer_len) == 0);
}

/*
 * Check if a certificate is expired or will expire soon.
 * Returns:
 *   0  = valid
 *   -EKEYEXPIRED = expired
 *   -EKEYREVOKED = expiring within grace period (strict mode)
 */
static int bc_check_cert_expiry(size_t idx, time64_t now, bool strict)
{
	struct bc_cert *c = &bc_certs[idx];
	time64_t grace_seconds = BOOT_CERTS_GRACE_DAYS * 86400;

	if (c->valid_to == 0)
		return 0;  /* No validity data - skip check */

	/* Check if expired */
	if (now > c->valid_to) {
		bc_dbg("cert idx=%zu EXPIRED (expired %lld seconds ago)\n",
		       idx, now - c->valid_to);
		return -EKEYEXPIRED;
	}

	/* Check if expiring soon (only in strict mode) */
	if (strict && (c->valid_to - now) < grace_seconds) {
		bc_dbg("cert idx=%zu expiring soon (in %lld days)\n",
		       idx, (c->valid_to - now) / 86400);
		return -EKEYREVOKED;  /* Abuse this code for "expiring soon" */
	}

	return 0;
}

/*
 * Scan all certificates and update expiry status.
 * Returns number of violations found (expired or expiring soon).
 */
static int bc_update_expiry_status(void)
{
	size_t i;
	time64_t now;
	int violations = 0;
	bool strict = (BOOT_CERTS_EXPIRY_POLICY == BC_EXPIRY_STRICT);

	now = ktime_get_real_seconds();
	expiry_status.last_check = now;
	expiry_status.expired_count = 0;
	expiry_status.expiring_soon_count = 0;
	expiry_status.earliest_expiry = 0;

	for (i = 0; i < bc_cert_count; i++) {
		struct bc_cert *c = &bc_certs[i];
		int ret;

		if (c->valid_to == 0)
			continue;

		/* Track earliest expiry */
		if (expiry_status.earliest_expiry == 0 ||
		    c->valid_to < expiry_status.earliest_expiry)
			expiry_status.earliest_expiry = c->valid_to;

		ret = bc_check_cert_expiry(i, now, strict);
		if (ret == -EKEYEXPIRED) {
			expiry_status.expired_count++;
			violations++;
		} else if (ret == -EKEYREVOKED) {
			expiry_status.expiring_soon_count++;
			violations++;
		}
	}

	return violations;
}

/*
 * Enforce certificate expiry policy.
 * Called at boot time and when adding new certificates.
 * Returns 0 if OK to proceed, negative error if should fail.
 */
static int bc_enforce_expiry_policy(void)
{
	int violations;
	enum boot_certs_expiry_policy policy = BOOT_CERTS_EXPIRY_POLICY;

	violations = bc_update_expiry_status();

	if (violations == 0)
		return 0;

	/* WARN policy: log but don't fail */
	if (policy == BC_EXPIRY_WARN) {
		if (expiry_status.expired_count > 0)
			pr_warn("boot_certs: %d expired certificate(s) found (WARN mode)\n",
				expiry_status.expired_count);
		if (expiry_status.expiring_soon_count > 0)
			pr_warn("boot_certs: %d certificate(s) expiring within %d days\n",
				expiry_status.expiring_soon_count,
				BOOT_CERTS_GRACE_DAYS);
		return 0;
	}

	/* REJECT policy: fail if any certs are expired */
	if (policy == BC_EXPIRY_REJECT) {
		if (expiry_status.expired_count > 0) {
			pr_err("boot_certs: %d expired certificate(s) - REJECTING (policy=REJECT)\n",
			       expiry_status.expired_count);
			boot_certs_poison(BC_V_CERT_EXPIRED);
			return -EKEYEXPIRED;
		}
		if (expiry_status.expiring_soon_count > 0) {
			pr_warn("boot_certs: %d certificate(s) expiring within %d days\n",
				expiry_status.expiring_soon_count,
				BOOT_CERTS_GRACE_DAYS);
		}
		return 0;
	}

	/* STRICT policy: fail if any certs are expired OR expiring soon */
	if (policy == BC_EXPIRY_STRICT) {
		if (expiry_status.expired_count > 0) {
			pr_err("boot_certs: %d expired certificate(s) - REJECTING (policy=STRICT)\n",
			       expiry_status.expired_count);
			boot_certs_poison(BC_V_CERT_EXPIRED);
			return -EKEYEXPIRED;
		}
		if (expiry_status.expiring_soon_count > 0) {
			pr_err("boot_certs: %d certificate(s) expiring within %d days - REJECTING (policy=STRICT)\n",
			       expiry_status.expiring_soon_count,
			       BOOT_CERTS_GRACE_DAYS);
			boot_certs_poison(BC_V_CERT_EXPIRING_SOON);
			return -EKEYREVOKED;
		}
		return 0;
	}

	return 0;
}

/*
 * Periodic expiry check workqueue handler.
 * Runs daily (or at configured interval) to check for expired certificates.
 */
static void bc_expiry_check_work_fn(struct work_struct *work)
{
	int violations;

	mutex_lock(&boot_certs_mutex);

	if (!boot_certs_sha_ok || bc_cert_count == 0) {
		mutex_unlock(&boot_certs_mutex);
		return;
	}

	violations = bc_update_expiry_status();

	if (violations > 0) {
		if (expiry_status.expired_count > 0)
			pr_warn("boot_certs: periodic check: %d expired certificate(s)\n",
				expiry_status.expired_count);
		if (expiry_status.expiring_soon_count > 0)
			pr_warn("boot_certs: periodic check: %d certificate(s) expiring within %d days\n",
				expiry_status.expiring_soon_count,
				BOOT_CERTS_GRACE_DAYS);
	}

	mutex_unlock(&boot_certs_mutex);

	/* Reschedule for next check */
	if (expiry_check_enabled) {
		schedule_delayed_work(&expiry_check_work,
				     BOOT_CERTS_CHECK_INTERVAL_HOURS * 60 * 60 * HZ);
	}
}

static int boot_certs_load_into_secondary_keyring(void)
{
#if !IS_ENABLED(CONFIG_SECONDARY_TRUSTED_KEYRING)
	return -EOPNOTSUPP;
#else
	size_t i;
	int ret;
	int root_count = 0;

	if (!boot_certs_sha_ok)
		return -EACCES;

	/*
	 * Two-phase loading:
	 * Phase 1: Add root CAs to both boot_root_certs and secondary_trusted_keys
	 * Phase 2: Add intermediate CAs only to secondary_trusted_keys
	 *
	 * This allows later sealing where:
	 * - boot_root_certs is sealed (no new roots)
	 * - secondary_trusted_keys accepts new certs signed by boot_root_certs
	 */

	/* Phase 1: Process root CAs */
	for (i = 0; i < bc_cert_count; i++) {
		char desc[64];

		if (!bc_is_root_ca(i))
			continue;

		snprintf(desc, sizeof(desc), "boot_root:%zu", i);

		/* Add to boot_root_certs keyring */
		ret = boot_root_certs_add_cert(bc_certs[i].der,
					       bc_certs[i].der_len,
					       desc);
		if (ret < 0) {
			bc_dbg("keyring: add root cert idx=%zu to boot_root_certs failed (err=%d)\n",
			       i, ret);
			return ret;
		}

		/* Also add to secondary for module signing */
		ret = secondary_trusted_keys_add_cert(bc_certs[i].der,
						     bc_certs[i].der_len,
						     desc);
		if (ret < 0) {
			bc_dbg("keyring: add root cert idx=%zu to secondary failed (err=%d)\n",
			       i, ret);
			return ret;
		}

		root_count++;
		bc_dbg("keyring: added root CA cert idx=%zu\n", i);
	}

	if (root_count == 0) {
		bc_dbg("keyring: WARNING - no root CA certificates found in chain\n");
		return -EINVAL;
	}

	/* Phase 2: Process intermediate CAs */
	for (i = 0; i < bc_cert_count; i++) {
		char desc[64];

		if (bc_is_root_ca(i))
			continue;  /* Already added in phase 1 */

		snprintf(desc, sizeof(desc), "boot_intermediate:%zu", i);

		/* Add only to secondary_trusted_keys */
		ret = secondary_trusted_keys_add_cert(bc_certs[i].der,
						     bc_certs[i].der_len,
						     desc);
		if (ret < 0) {
			bc_dbg("keyring: add intermediate cert idx=%zu failed (err=%d)\n",
			       i, ret);
			return ret;
		}

		bc_dbg("keyring: added intermediate CA cert idx=%zu\n", i);
	}

	pr_info("boot_certs: loaded %d root CAs, %zu total certs into keyrings\n",
		root_count, bc_cert_count);

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
		/* Return -ENOENT as-is so caller can retry; poison on other errors */
		if (err != -ENOENT)
			boot_certs_poison(BC_V_PATH_LOOKUP);
		return err;
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

	/* Additional check: ensure size fits in size_t for safe cast */
	if ((size_t)size != size || (size_t)size > SIZE_MAX) {
		bc_dbg("file: size too large for platform: %lld\n", (long long)size);
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

	/* Ensure we don't overflow buffer (n is guaranteed <= BOOT_CERTS_CMDLINE_MAX) */
	if (n > BOOT_CERTS_CMDLINE_MAX) {
		bc_dbg("cmdline: read size exceeds maximum (%zd > %u)\n",
		       n, BOOT_CERTS_CMDLINE_MAX);
		kfree(buf);
		return -E2BIG;
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
			/* Check for overflow before shift */
			if (l > (SIZE_MAX >> 8))
				return -EINVAL;
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
 * Simplified time parser for ASN.1 Time (UTCTime or GeneralizedTime).
 * This is a minimal implementation - for production, consider using
 * the kernel's x509_decode_time() from crypto/asymmetric_keys/.
 *
 * Returns 0 on success, negative on error.
 */
static int bc_asn1_parse_time(u8 tag, const u8 *data, size_t len, time64_t *out)
{
	struct tm tm;
	int year, month, day, hour, min, sec;
	int offset = 0;

	memset(&tm, 0, sizeof(tm));

	/* UTCTime: YYMMDDHHMMSSZ (tag 0x17) */
	if (tag == 0x17) {
		if (len < 13)
			return -EINVAL;
		/* YY */
		year = (data[0] - '0') * 10 + (data[1] - '0');
		/* Y2K fix: 00-49 = 2000-2049, 50-99 = 1950-1999 */
		year += (year < 50) ? 2000 : 1900;
		offset = 2;
	}
	/* GeneralizedTime: YYYYMMDDHHMMSSZ (tag 0x18) */
	else if (tag == 0x18) {
		if (len < 15)
			return -EINVAL;
		/* YYYY */
		year = (data[0] - '0') * 1000 + (data[1] - '0') * 100 +
		       (data[2] - '0') * 10 + (data[3] - '0');
		offset = 4;
	} else {
		return -EINVAL;
	}

	/* Parse MMDDHHMMSS */
	month = (data[offset]     - '0') * 10 + (data[offset + 1] - '0');
	day   = (data[offset + 2] - '0') * 10 + (data[offset + 3] - '0');
	hour  = (data[offset + 4] - '0') * 10 + (data[offset + 5] - '0');
	min   = (data[offset + 6] - '0') * 10 + (data[offset + 7] - '0');
	sec   = (data[offset + 8] - '0') * 10 + (data[offset + 9] - '0');

	/* Basic validation */
	if (month < 1 || month > 12 || day < 1 || day > 31 ||
	    hour > 23 || min > 59 || sec > 59)
		return -EINVAL;

	/* Convert to time64_t (seconds since epoch) */
	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;

	*out = mktime64(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec);
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
		{
			struct bc_asn1 validity;
			const u8 *validity_start;
			size_t validity_len;
			u8 validity_tag;
			const u8 *time_val;
			size_t time_len;
			u8 time_tag;

			validity_start = t.p;
			if (bc_asn1_get_tag_len(&t, &validity_tag, &validity_len, &val))
				return -EINVAL;
			if (validity_tag != 0x30)
				return -EINVAL;

			/* Parse Validity SEQUENCE contents */
			validity.p = val;
			validity.end = val + validity_len;

			/* notBefore (Time) */
			if (bc_asn1_get_tag_len(&validity, &time_tag, &time_len, &time_val))
				return -EINVAL;
			if (bc_asn1_parse_time(time_tag, time_val, time_len, &c->valid_from))
				c->valid_from = 0;  /* Parse error - zero it out */

			/* notAfter (Time) */
			if (bc_asn1_get_tag_len(&validity, &time_tag, &time_len, &time_val))
				return -EINVAL;
			if (bc_asn1_parse_time(time_tag, time_val, time_len, &c->valid_to))
				c->valid_to = 0;  /* Parse error - zero it out */
		}

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

		/* Check for potential overflow in size calculation */
		if (check_mul_overflow((b64_clean_len + 3) / 4, 3UL, &der_max)) {
#ifdef BOOT_CERTS_DEBUG
			pr_info("boot_certs: pem: der_max calculation overflow (cert=%zu clean=%zu)\n",
				count, b64_clean_len);
#endif
			kfree(b64_clean);
			return -EINVAL;
		}

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
	ssize_t ret;

	snprintf(path, sizeof(path), "%s/%s", BOOT_CERTS_BOOT_PATH, BOOT_CERTS_CERT_REL);

	mutex_lock(&boot_certs_mutex);

	if (boot_certs_check_policy(path)) {
		ret = -EACCES;
		goto out;
	}

	if (!boot_certs_sha_ok) {
		ret = -EACCES;
		goto out;
	}

	if (!chain_buf || !chain_len) {
		ret = -ENODATA;
		goto out;
	}

	if (off < 0) {
		ret = -EINVAL;
		goto out;
	}

	if ((size_t)off >= chain_len) {
		ret = 0;
		goto out;
	}

	avail = chain_len - (size_t)off;
	if (cnt > avail)
		cnt = avail;

	memcpy(buf, (u8 *)chain_buf + off, cnt);
	ret = (ssize_t)cnt;

out:
	mutex_unlock(&boot_certs_mutex);
	return ret;
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
	ssize_t ret;

	mutex_lock(&boot_certs_mutex);
	ret = scnprintf(b, PAGE_SIZE, "%s\n", boot_certs_sha_ok ? "true" : "false");
	mutex_unlock(&boot_certs_mutex);

	return ret;
}
static struct kobj_attribute ok_attr = __ATTR_RO(ok);

static ssize_t sealed_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	ssize_t ret;

	mutex_lock(&boot_certs_mutex);
	ret = scnprintf(b, PAGE_SIZE, "%s\n", boot_certs_sealed ? "true" : "false");
	mutex_unlock(&boot_certs_mutex);

	return ret;
}

#if IS_ENABLED(CONFIG_BOOT_CERTS_ALLOW_SYSFS_SEAL)
static ssize_t sealed_store(struct kobject *k, struct kobj_attribute *a,
			    const char *buf, size_t count)
{
	bool v;
	int ret;
	ssize_t result;

	if (sysfs_streq(buf, "1") || sysfs_streq(buf, "true"))
		v = true;
	else if (sysfs_streq(buf, "0") || sysfs_streq(buf, "false"))
		return -EINVAL; /* cannot unseal */
	else
		return -EINVAL;

	if (!v)
		return -EINVAL;

	mutex_lock(&boot_certs_mutex);

	if (!boot_certs_sha_ok) {
		result = -EACCES;
		goto out;
	}

	if (boot_certs_sealed) {
		result = count;
		goto out;
	}

	ret = boot_certs_secondary_trusted_keys_seal();
	if (ret) {
		bc_dbg("seal: failed/unsupported (err=%d)\n", ret);
		boot_certs_poison(BC_V_SEAL);
		result = ret;
		goto out;
	}

	boot_certs_sealed = true;
	result = count;

out:
	mutex_unlock(&boot_certs_mutex);
	return result;
}

static struct kobj_attribute sealed_attr =
	__ATTR(sealed, 0644, sealed_show, sealed_store);
#else
static struct kobj_attribute sealed_attr = __ATTR_RO(sealed);
#endif

static ssize_t status_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	ssize_t ret;

	mutex_lock(&boot_certs_mutex);
	ret = scnprintf(b, PAGE_SIZE,
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
	mutex_unlock(&boot_certs_mutex);

	return ret;
}
static struct kobj_attribute status_attr = __ATTR_RO(status);

static ssize_t expiry_status_show(struct kobject *k, struct kobj_attribute *a, char *b)
{
	ssize_t ret;
	time64_t now;
	long long days_until_expiry = 0;

	mutex_lock(&boot_certs_mutex);
	now = ktime_get_real_seconds();

	if (expiry_status.earliest_expiry > 0)
		days_until_expiry = (expiry_status.earliest_expiry - now) / 86400;

	ret = scnprintf(b, PAGE_SIZE,
			"policy=%s grace_days=%d expired=%d expiring_soon=%d "
			"last_check=%lld earliest_expiry_days=%lld check_enabled=%d\n",
			(BOOT_CERTS_EXPIRY_POLICY == BC_EXPIRY_WARN) ? "WARN" :
			(BOOT_CERTS_EXPIRY_POLICY == BC_EXPIRY_REJECT) ? "REJECT" : "STRICT",
			BOOT_CERTS_GRACE_DAYS,
			expiry_status.expired_count,
			expiry_status.expiring_soon_count,
			expiry_status.last_check,
			days_until_expiry,
			expiry_check_enabled);
	mutex_unlock(&boot_certs_mutex);

	return ret;
}
static struct kobj_attribute expiry_status_attr = __ATTR_RO(expiry_status);

static ssize_t expiry_check_now_store(struct kobject *k, struct kobj_attribute *a,
				      const char *buf, size_t count)
{
	int violations;

	if (!sysfs_streq(buf, "1"))
		return -EINVAL;

	mutex_lock(&boot_certs_mutex);

	if (!boot_certs_sha_ok || bc_cert_count == 0) {
		mutex_unlock(&boot_certs_mutex);
		return -ENODATA;
	}

	violations = bc_update_expiry_status();

	pr_info("boot_certs: manual expiry check: expired=%d expiring_soon=%d\n",
		expiry_status.expired_count,
		expiry_status.expiring_soon_count);

	mutex_unlock(&boot_certs_mutex);

	return count;
}
static struct kobj_attribute expiry_check_now_attr =
	__ATTR(expiry_check_now, 0200, NULL, expiry_check_now_store);

static struct attribute *attrs[] = {
	&ok_attr.attr,
	&sealed_attr.attr,
	&status_attr.attr,
	&expiry_status_attr.attr,
	&expiry_check_now_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attrs,
};

/* ---------- U-Boot memory address support ---------- */

/*
 * Boot parameter: boot_certs.addr=0x12345678
 * Physical address where U-Boot placed certificate chain from FIT image
 */
static int __init boot_certs_addr_setup(char *str)
{
	boot_certs_addr = simple_strtoul(str, NULL, 0);
	return 1;
}
__setup("boot_certs.addr=", boot_certs_addr_setup);

/*
 * Boot parameter: boot_certs.len=4096
 * Length of certificate chain in bytes
 */
static int __init boot_certs_len_setup(char *str)
{
	boot_certs_len = simple_strtoul(str, NULL, 0);
	return 1;
}
__setup("boot_certs.len=", boot_certs_len_setup);

/*
 * Read certificate chain from memory address (provided by U-Boot from FIT image)
 * This is the preferred method for production - no filesystem dependency.
 *
 * Priority:
 *   1. Kconfig fixed address (CONFIG_BOOT_CERTS_USE_MEM_ADDR) - for testing
 *   2. Boot parameters (boot_certs.addr/len) - for production U-Boot FIT
 */
static int boot_certs_read_from_memory(void)
{
	void *virt_addr;
	unsigned long addr = boot_certs_addr;
	unsigned long len = boot_certs_len;

#ifdef CONFIG_BOOT_CERTS_USE_MEM_ADDR
	/* Use Kconfig values if enabled (testing mode) */
	if (!addr || !len) {
		addr = CONFIG_BOOT_CERTS_MEM_ADDR;
		len = CONFIG_BOOT_CERTS_MEM_LEN;
		bc_dbg("memory: using Kconfig addr=0x%lx len=%lu\n", addr, len);
	}
#endif

	if (!addr || !len) {
		bc_dbg("memory: addr or len not provided\n");
		return -EINVAL;
	}

	if (len > CONFIG_BOOT_CERTS_MAX_BYTES) {
		pr_err("boot_certs: memory: len %lu exceeds max %d\n",
		       len, CONFIG_BOOT_CERTS_MAX_BYTES);
		return -EINVAL;
	}

	/* Map physical address to kernel virtual address */
	virt_addr = memremap(addr, len, MEMREMAP_WB);
	if (!virt_addr) {
		pr_err("boot_certs: memory: failed to remap 0x%lx (len=%lu)\n",
		       addr, len);
		return -ENOMEM;
	}

	/* Allocate kernel buffer and copy */
	chain_buf = kvmalloc(len, GFP_KERNEL);
	if (!chain_buf) {
		memunmap(virt_addr);
		return -ENOMEM;
	}

	memcpy(chain_buf, virt_addr, len);
	chain_len = len;

	memunmap(virt_addr);

	bc_dbg("memory: loaded %zu bytes from phys 0x%lx\n",
	       chain_len, addr);

	return 0;
}

/* ---------- init / exit ---------- */

/*
 * Mount retry work: called when /boot/firmware isn't mounted yet
 * Retries every 100ms until mount appears or max retries exceeded
 */
static int boot_certs_complete_init(void)
{
	u8 expected[BOOT_CERTS_DIGEST_LEN];
	u8 actual[BOOT_CERTS_DIGEST_LEN];
	int ret;

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

	/* Enforce certificate expiry policy */
	ret = bc_enforce_expiry_policy();
	if (ret) {
		bc_dbg("expiry: policy enforcement failed (err=%d)\n", ret);
		goto out_fail;
	}

	ret = boot_certs_load_into_secondary_keyring();
	if (ret) {
		bc_dbg("keyring: load failed (err=%d)\n", ret);
		boot_certs_poison(BC_V_SEAL); /* or a new violation like BC_V_KEYRING */
		goto out_fail;
	}

	/* Create kobject if it doesn't exist (it exists if userspace-triggered) */
	if (!boot_certs_kobj) {
		boot_certs_kobj = kobject_create_and_add(BOOT_CERTS_DIRNAME, kernel_kobj);
		if (!boot_certs_kobj) {
			boot_certs_poison(BC_V_SYSFS);
			ret = -ENOMEM;
			goto out_fail;
		}
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

	/* Initialize periodic expiry checking */
#if IS_ENABLED(CONFIG_BOOT_CERTS_EXPIRY_CHECK_DAILY)
	INIT_DELAYED_WORK(&expiry_check_work, bc_expiry_check_work_fn);
	expiry_check_enabled = true;
	schedule_delayed_work(&expiry_check_work,
			     BOOT_CERTS_CHECK_INTERVAL_HOURS * 60 * 60 * HZ);
	pr_info("boot_certs: scheduled expiry checks every %d hours\n",
		BOOT_CERTS_CHECK_INTERVAL_HOURS);
#endif

	{
		int rc = 0;
		size_t ci;
		for (ci = 0; ci < bc_cert_count; ci++)
			if (bc_is_root_ca(ci))
				rc++;
		pr_info("boot_certs: OK, exported %zu bytes at /sys/kernel/%s/chain.pem "
			"(policy=%s, %d root CAs, %zu total certs)\n",
			chain_len, BOOT_CERTS_DIRNAME,
			(BOOT_CERTS_EXPIRY_POLICY == BC_EXPIRY_WARN) ? "WARN" :
			(BOOT_CERTS_EXPIRY_POLICY == BC_EXPIRY_REJECT) ? "REJECT" : "STRICT",
			rc, bc_cert_count);
	}
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
	return ret;
}

/* Forward declaration for sysfs trigger */
static struct kobj_attribute initialize_attr;

/* Sysfs trigger for delayed initialization from userspace */
static ssize_t initialize_store(struct kobject *kobj, struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	char path[sizeof(BOOT_CERTS_BOOT_PATH) + 1 + sizeof(BOOT_CERTS_CERT_REL)];
	int ret;

	if (boot_certs_sha_ok) {
		pr_warn("boot_certs: already initialized\n");
		return -EEXIST;
	}

	pr_info("boot_certs: userspace trigger - loading from filesystem\n");

	snprintf(path, sizeof(path), "%s/%s", BOOT_CERTS_BOOT_PATH, BOOT_CERTS_CERT_REL);

	ret = boot_certs_check_policy(path);
	if (ret) {
		pr_err("boot_certs: check_policy failed: %d\n", ret);
		boot_certs_poison(BC_V_PATH_LOOKUP);
		return ret;
	}

	ret = boot_certs_read_file_once(path);
	if (ret) {
		boot_certs_poison(BC_V_PATH_LOOKUP);
		return ret;
	}

	ret = boot_certs_complete_init();
	if (ret)
		return ret;

	pr_info("boot_certs: initialization complete via userspace trigger\n");
	return count;
}

static struct kobj_attribute initialize_attr = __ATTR_WO(initialize);

static int __init boot_certs_init(void)
{
	char path[sizeof(BOOT_CERTS_BOOT_PATH) + 1 + sizeof(BOOT_CERTS_CERT_REL)];
	int ret;

	pr_info("boot_certs: INIT STARTED at %lu jiffies\n", jiffies);

	boot_certs_sha_ok = false;
	boot_certs_sealed = false;
	boot_certs_last_violation = BC_V_NONE;

	/*
	 * Try U-Boot memory address first (production FIT image method).
	 * Falls back to filesystem for R&D/testing.
	 */
	ret = boot_certs_read_from_memory();
	if (ret == 0) {
		bc_dbg("using certificates from U-Boot memory (FIT image)\n");
	} else {
		bc_dbg("U-Boot memory not available, trying filesystem\n");

		snprintf(path, sizeof(path), "%s/%s", BOOT_CERTS_BOOT_PATH, BOOT_CERTS_CERT_REL);

		ret = boot_certs_check_policy(path);
		if (ret == -ENOENT) {
			/* /boot/firmware not mounted - create sysfs trigger for userspace */
			pr_info("boot_certs: /boot/firmware not ready, creating sysfs trigger\n");

			boot_certs_kobj = kobject_create_and_add(BOOT_CERTS_DIRNAME, kernel_kobj);
			if (!boot_certs_kobj)
				return -ENOMEM;

			ret = sysfs_create_file(boot_certs_kobj, &initialize_attr.attr);
			if (ret) {
				kobject_put(boot_certs_kobj);
				boot_certs_kobj = NULL;
				return ret;
			}

			pr_info("boot_certs: created /sys/kernel/boot_certs/initialize - waiting for userspace\n");
			return 0;  /* Userspace will trigger initialization */
		}
		if (ret) {
			boot_certs_poison(BC_V_PATH_LOOKUP);
			return -EKEYREJECTED;
		}

		ret = boot_certs_read_file_once(path);
		if (ret) {
			boot_certs_poison(BC_V_PATH_LOOKUP);
			return -EKEYREJECTED;
		}
	}

	/* Complete initialization (parse, hash check, keyring load, sysfs) */
	return boot_certs_complete_init();
}

/*
 * Note: This code is built into the kernel, not a module.
 * The exit function is included for completeness but won't be called
 * in normal operation. Resources remain allocated for the lifetime
 * of the kernel.
 */
static void boot_certs_exit(void)
{
	/* Cancel periodic expiry checks */
#if IS_ENABLED(CONFIG_BOOT_CERTS_EXPIRY_CHECK_DAILY)
	expiry_check_enabled = false;
	cancel_delayed_work_sync(&expiry_check_work);
#endif

	/*
	 * Remove sysfs files first to prevent new accesses.
	 * kobject_put() will wait for existing sysfs operations to complete
	 * before returning, ensuring no use-after-free.
	 */
	if (boot_certs_kobj) {
		sysfs_remove_bin_file(boot_certs_kobj, &chain_attr);
		sysfs_remove_group(boot_certs_kobj, &attr_group);
		kobject_put(boot_certs_kobj);
		boot_certs_kobj = NULL;
	}

	/*
	 * After sysfs cleanup, all operations are complete.
	 * Safe to free resources under mutex protection.
	 */
	mutex_lock(&boot_certs_mutex);
	bc_pem_free_all();
	kvfree(chain_buf);
	chain_buf = NULL;
	chain_len = 0;
	mutex_unlock(&boot_certs_mutex);
}

/*
 * Initialization timing considerations:
 *
 * With U-Boot FIT + memory address (production):
 *   - Can use late_initcall (early, no filesystem dependency)
 *   - Certificates already in memory from bootloader
 *
 * With filesystem fallback (testing /boot/firmware):
 *   - Needs device_initcall_sync (late, after userspace mounts)
 *   - /boot/firmware mounted by systemd/fstab before this runs
 *
 * device_initcall_sync is:
 *   - Late enough for filesystem mounts
 *   - Early enough to complete before module loading
 *   - Safe for both memory and filesystem methods
 *
 * Future: FIT image integration will allow switching back to late_initcall.
 */
device_initcall_sync(boot_certs_init);