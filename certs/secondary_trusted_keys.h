/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SECONDARY_TRUSTED_KEYS_H
#define _LINUX_SECONDARY_TRUSTED_KEYS_H

#include <linux/types.h>

int secondary_trusted_keys_add_cert(const void *der, size_t der_len,
				   const char *desc);
int secondary_trusted_keys_seal(void);

#endif