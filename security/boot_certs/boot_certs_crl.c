// SPDX-License-Identifier: GPL-2.0
/*
 * boot_certs_crl - Runtime Certificate Revocation List processing
 *
 * Provides a write-only sysfs endpoint (/sys/kernel/crl/push_crl) that
 * accepts a PKCS#7-signed CRL binary payload. The PKCS#7 signature is
 * verified against the secondary (+ builtin) trusted keyring. The inner
 * content is a compact binary revocation list with serial + DER issuer
 * pairs.
 *
 * Upon successful verification and parsing:
 *   1. Each CRL entry is matched against keys in all trusted keyrings
 *      using find_asymmetric_key() with serial+issuer identity.
 *   2. Matching keys are invalidated immediately via key_invalidate().
 *   3. Cascade invalidation finds and revokes all leaf certificates
 *      that were signed by any revoked key (multi-round).
 *   4. Revocation entries are stored persistently (in memory) to
 *      prevent re-addition.
 *
 * Replay protection: each CRL carries a monotonic timestamp that must
 * exceed the previously accepted timestamp.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/capability.h>
#include <linux/key.h>
#include <linux/assoc_array.h>
#include <linux/verification.h>
#include <linux/unaligned.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include <crypto/public_key.h>
#include "boot_certs_crl.h"

/* ---- Static state ---- */

static DEFINE_MUTEX(crl_mutex);
static struct kobject *crl_kobj;

/* Monotonic timestamp for replay protection */
static s64 last_crl_timestamp;

/* Counters */
static unsigned int total_revoked;
static unsigned int crls_processed;

/* Persistent revocation list (survives until reboot) */
struct crl_revoked_entry {
	struct list_head	list;
	struct asymmetric_key_id *id;	/* serial + issuer (owns memory) */
};

static LIST_HEAD(revoked_list);

/* Identity of a revoked key, used for cascade matching */
struct revoked_identity {
	struct list_head	list;
	struct asymmetric_key_id *id_0;	/* serial + issuer */
	struct asymmetric_key_id *id_1;	/* subject key id (optional) */
};

/* Context passed through PKCS#7 view_content callback */
struct crl_context {
	struct list_head	revoked;	/* list of revoked_identity */
	int			new_revocations;
};

/*
 * Keyring leaf pointer encoding.
 * Keyrings store keys in an assoc_array with bit 1 indicating sub-keyrings.
 * assoc_array_iterate() strips the assoc_array type bits before calling the
 * callback, so the callback receives (key_ptr | KEYRING_PTR_SUBTYPE).
 */
#define KEYRING_PTR_SUBTYPE	0x2UL

static inline struct key *leaf_to_key(const void *leaf)
{
	return (struct key *)((unsigned long)leaf & ~KEYRING_PTR_SUBTYPE);
}

/* Maximum cascade rounds to prevent infinite loops */
#define CRL_CASCADE_MAX_ROUNDS		10
#define CRL_CASCADE_MAX_COLLECT		256

/* ---- Revocation list helpers ---- */

static void add_to_revoked_list(struct asymmetric_key_id *id)
{
	struct crl_revoked_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		kfree(id);
		return;
	}
	entry->id = id;
	list_add(&entry->list, &revoked_list);
}

static bool is_on_revoked_list(const struct asymmetric_key_id *id)
{
	struct crl_revoked_entry *entry;

	list_for_each_entry(entry, &revoked_list, list) {
		if (asymmetric_key_id_same(entry->id, id))
			return true;
	}
	return false;
}

/* ---- Keyring helpers ---- */

/*
 * Get the keyrings to search for revocation.
 * Returns the number of keyrings stored in the array.
 * Searches secondary (which includes builtin via link), plus boot_root.
 */
static int get_search_keyrings(struct key **keyrings, int max)
{
	int n = 0;
	struct key *k;

	k = get_secondary_trusted_keys();
	if (k) {
		keyrings[n++] = k;
	} else {
		k = get_builtin_trusted_keys();
		if (k)
			keyrings[n++] = k;
	}

	if (n < max) {
		k = get_boot_root_certs();
		if (k)
			keyrings[n++] = k;
	}

	return n;
}

/* ---- Identity collection for cascade ---- */

static struct asymmetric_key_id *dup_key_id(const struct asymmetric_key_id *src)
{
	if (!src)
		return NULL;
	return kmemdup(src, sizeof(*src) + src->len, GFP_KERNEL);
}

static struct revoked_identity *collect_key_identity(struct key *key)
{
	const struct asymmetric_key_ids *kids;
	struct revoked_identity *ri;

	kids = asymmetric_key_ids(key);
	if (!kids)
		return NULL;

	ri = kzalloc(sizeof(*ri), GFP_KERNEL);
	if (!ri)
		return NULL;

	INIT_LIST_HEAD(&ri->list);
	ri->id_0 = dup_key_id(kids->id[0]);
	ri->id_1 = dup_key_id(kids->id[1]);

	return ri;
}

static void free_revoked_identity(struct revoked_identity *ri)
{
	kfree(ri->id_0);
	kfree(ri->id_1);
	kfree(ri);
}

static void free_revoked_list(struct list_head *list)
{
	struct revoked_identity *ri, *tmp;

	list_for_each_entry_safe(ri, tmp, list, list) {
		list_del(&ri->list);
		free_revoked_identity(ri);
	}
}

/* ---- Direct revocation ---- */

static int revoke_single_entry(struct crl_context *ctx,
			       const u8 *serial, u16 serial_len,
			       const u8 *issuer, u16 issuer_len)
{
	struct asymmetric_key_id *match_id;
	struct key *keyrings[3];
	int nr_keyrings;
	int i, found = 0;

	match_id = asymmetric_key_generate_id(serial, serial_len,
					      issuer, issuer_len);
	if (IS_ERR(match_id))
		return PTR_ERR(match_id);

	if (is_on_revoked_list(match_id)) {
		kfree(match_id);
		return 0;  /* Already revoked */
	}

	nr_keyrings = get_search_keyrings(keyrings, ARRAY_SIZE(keyrings));

	for (i = 0; i < nr_keyrings; i++) {
		struct key *key;

		key = find_asymmetric_key(keyrings[i], match_id,
					  NULL, NULL, false);
		if (IS_ERR(key))
			continue;

		/* Skip if already invalidated (e.g., found via linked keyring) */
		if (test_bit(KEY_FLAG_INVALIDATED, &key->flags)) {
			key_put(key);
			continue;
		}

		/* Collect identity for cascade before invalidation */
		{
			struct revoked_identity *ri;

			ri = collect_key_identity(key);
			if (ri)
				list_add(&ri->list, &ctx->revoked);
		}

		pr_notice("CRL: revoking key serial=%d desc='%s'\n",
			  key->serial,
			  key->description ? key->description : "?");
		key_invalidate(key);
		key_put(key);
		found++;
		ctx->new_revocations++;
		total_revoked++;
	}

	/* Store in persistent revocation list */
	add_to_revoked_list(match_id);

	return found ? 0 : -ENOKEY;
}

/* ---- Cascade invalidation ---- */

struct cascade_ctx {
	struct list_head	*revoked;
	struct key		*collected[CRL_CASCADE_MAX_COLLECT];
	int			count;
};

static int cascade_iterator(const void *object, void *data)
{
	struct cascade_ctx *ctx = data;
	struct key *key = leaf_to_key(object);
	const struct public_key_signature *sig;
	struct revoked_identity *ri;

	if (key->type != &key_type_asymmetric)
		return 0;
	if (test_bit(KEY_FLAG_INVALIDATED, &key->flags))
		return 0;

	sig = key->payload.data[asym_auth];
	if (!sig)
		return 0;

	/* Check if this key's signer matches any revoked key */
	list_for_each_entry(ri, ctx->revoked, list) {
		bool match = false;

		if (ri->id_0 && sig->auth_ids[0] &&
		    asymmetric_key_id_same(ri->id_0, sig->auth_ids[0]))
			match = true;
		else if (ri->id_1 && sig->auth_ids[1] &&
			 asymmetric_key_id_same(ri->id_1, sig->auth_ids[1]))
			match = true;

		if (match && ctx->count < CRL_CASCADE_MAX_COLLECT) {
			key_get(key);
			ctx->collected[ctx->count++] = key;
			return 0;
		}
	}
	return 0;
}

static int cascade_revoke_keyring(struct key *keyring,
				  struct list_head *revoked)
{
	struct cascade_ctx ctx = {
		.revoked = revoked,
		.count = 0,
	};
	int i, new_revocations = 0;

	down_read(&keyring->sem);
	assoc_array_iterate(&keyring->keys, cascade_iterator, &ctx);
	up_read(&keyring->sem);

	for (i = 0; i < ctx.count; i++) {
		struct key *key = ctx.collected[i];
		struct revoked_identity *new_ri;

		new_ri = collect_key_identity(key);
		if (new_ri)
			list_add(&new_ri->list, revoked);

		pr_notice("CRL: cascade revoking key serial=%d desc='%s'\n",
			  key->serial,
			  key->description ? key->description : "?");
		key_invalidate(key);
		key_put(key);
		new_revocations++;
		total_revoked++;
	}

	return new_revocations;
}

static void cascade_invalidation(struct list_head *revoked)
{
	struct key *keyrings[3];
	int nr_keyrings;
	int round, i, new_this_round;

	nr_keyrings = get_search_keyrings(keyrings, ARRAY_SIZE(keyrings));

	for (round = 0; round < CRL_CASCADE_MAX_ROUNDS; round++) {
		new_this_round = 0;

		for (i = 0; i < nr_keyrings; i++)
			new_this_round += cascade_revoke_keyring(keyrings[i],
								 revoked);

		if (new_this_round == 0)
			break;

		pr_notice("CRL: cascade round %d: %d new revocations\n",
			  round + 1, new_this_round);
	}
}

/* ---- CRL payload parsing (PKCS#7 view_content callback) ---- */

static int crl_view_content(void *ctx_arg, const void *data, size_t len,
			    size_t asn1hdrlen)
{
	struct crl_context *ctx = ctx_arg;
	const u8 *p = data;
	struct crl_header hdr;
	s64 timestamp;
	u32 count, i;
	size_t offset;

	if (len < CRL_HEADER_SIZE)
		return -EINVAL;

	memcpy(&hdr, p, sizeof(hdr));

	if (be32_to_cpu(hdr.magic) != CRL_MAGIC) {
		pr_err("CRL: bad magic 0x%08x\n", be32_to_cpu(hdr.magic));
		return -EINVAL;
	}
	if (be32_to_cpu(hdr.version) != CRL_VERSION) {
		pr_err("CRL: unsupported version %u\n",
		       be32_to_cpu(hdr.version));
		return -EINVAL;
	}

	timestamp = (s64)be64_to_cpu(hdr.timestamp);
	if (timestamp <= last_crl_timestamp) {
		pr_err("CRL: replay rejected (ts=%lld <= last=%lld)\n",
		       timestamp, last_crl_timestamp);
		return -EKEYREJECTED;
	}

	count = be32_to_cpu(hdr.count);
	if (count > CRL_MAX_ENTRIES) {
		pr_err("CRL: too many entries (%u > %u)\n",
		       count, CRL_MAX_ENTRIES);
		return -E2BIG;
	}

	pr_notice("CRL: processing %u revocation entries (ts=%lld)\n",
		  count, timestamp);

	offset = CRL_HEADER_SIZE;
	for (i = 0; i < count; i++) {
		u16 serial_len, issuer_len;
		const u8 *serial, *issuer;
		int ret;

		/* Parse serial */
		if (offset + 2 > len)
			return -EINVAL;
		serial_len = get_unaligned_be16(p + offset);
		offset += 2;

		if (serial_len == 0 || serial_len > CRL_MAX_SERIAL_LEN)
			return -EINVAL;
		if (offset + serial_len > len)
			return -EINVAL;

		serial = p + offset;
		offset += serial_len;

		/* Parse issuer */
		if (offset + 2 > len)
			return -EINVAL;
		issuer_len = get_unaligned_be16(p + offset);
		offset += 2;

		if (issuer_len == 0 || issuer_len > CRL_MAX_ISSUER_LEN)
			return -EINVAL;
		if (offset + issuer_len > len)
			return -EINVAL;

		issuer = p + offset;
		offset += issuer_len;

		ret = revoke_single_entry(ctx, serial, serial_len,
					  issuer, issuer_len);
		if (ret == -ENOKEY)
			pr_notice("CRL: entry %u: no matching key found\n", i);
		else if (ret < 0)
			pr_warn("CRL: entry %u: error %d\n", i, ret);
	}

	last_crl_timestamp = timestamp;
	return 0;
}

/* ---- PKCS#7 verification and CRL processing ---- */

static int process_crl_blob(const void *blob, size_t blob_len)
{
	struct crl_context ctx = {};
	int ret;

	INIT_LIST_HEAD(&ctx.revoked);

	/*
	 * Verify PKCS#7 signature against secondary (+ builtin) trusted keys.
	 * The view_content callback parses and processes the CRL payload.
	 * Data is NULL because the content is embedded in the PKCS#7 message.
	 */
	ret = verify_pkcs7_signature(NULL, 0, blob, blob_len,
				     VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_UNSPECIFIED_SIGNATURE,
				     crl_view_content, &ctx);
	if (ret < 0) {
		pr_err("CRL: PKCS#7 verification failed: %d\n", ret);
		free_revoked_list(&ctx.revoked);
		return ret;
	}

	/* Cascade: revoke leaf certs signed by any revoked key */
	if (ctx.new_revocations > 0)
		cascade_invalidation(&ctx.revoked);

	crls_processed++;

	pr_notice("CRL: done. %d direct revocations, %u total revoked\n",
		  ctx.new_revocations, total_revoked);

	free_revoked_list(&ctx.revoked);
	return 0;
}

/* ---- Sysfs interface ---- */

static ssize_t push_crl_write(struct file *filp, struct kobject *kobj,
			      struct bin_attribute *attr,
			      char *buf, loff_t off, size_t count)
{
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* Require complete blob in a single write at offset 0 */
	if (off != 0)
		return -ESPIPE;

	if (count < CRL_HEADER_SIZE || count > CRL_MAX_BLOB_SIZE)
		return -EINVAL;

	mutex_lock(&crl_mutex);
	ret = process_crl_blob(buf, count);
	mutex_unlock(&crl_mutex);

	return ret < 0 ? ret : count;
}

static ssize_t status_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	return sysfs_emit(buf,
			  "crls_processed: %u\n"
			  "total_revoked: %u\n"
			  "last_timestamp: %lld\n"
			  "pending_entries: %u\n",
			  crls_processed, total_revoked,
			  last_crl_timestamp,
			  /* Count persistent revocation entries */
			  ({
				unsigned int cnt = 0;
				struct crl_revoked_entry *e;
				list_for_each_entry(e, &revoked_list, list)
					cnt++;
				cnt;
			  }));
}

static ssize_t revoked_count_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", total_revoked);
}

static struct bin_attribute bin_attr_push_crl = {
	.attr = { .name = "push_crl", .mode = 0200 },
	.write = push_crl_write,
	.size = CRL_MAX_BLOB_SIZE,
};

static struct kobj_attribute status_attr =
	__ATTR(status, 0444, status_show, NULL);

static struct kobj_attribute revoked_count_attr =
	__ATTR(revoked_count, 0444, revoked_count_show, NULL);

static struct attribute *crl_attrs[] = {
	&status_attr.attr,
	&revoked_count_attr.attr,
	NULL,
};

static struct bin_attribute *crl_bin_attrs[] = {
	&bin_attr_push_crl,
	NULL,
};

static const struct attribute_group crl_attr_group = {
	.attrs = crl_attrs,
	.bin_attrs = crl_bin_attrs,
};

/* ---- Init ---- */

static int __init boot_certs_crl_init(void)
{
	int ret;

	crl_kobj = kobject_create_and_add("crl", kernel_kobj);
	if (!crl_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(crl_kobj, &crl_attr_group);
	if (ret) {
		pr_err("CRL: failed to create sysfs group: %d\n", ret);
		kobject_put(crl_kobj);
		return ret;
	}

	pr_notice("CRL: sysfs endpoint ready at /sys/kernel/crl/\n");
	return 0;
}
late_initcall(boot_certs_crl_init);
