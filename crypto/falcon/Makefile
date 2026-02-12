# SPDX-License-Identifier: GPL-2.0
#
# Makefile for FALCON post-quantum signature verification
#

obj-$(CONFIG_CRYPTO_FALCON) += falcon.o

falcon-y := falcon_verify.o \
            pqclean_verify.o \
            vrfy.o \
            codec.o \
            common.o \
            fpr.o

# FALCON verification benefits from compiler optimization
# (Reference implementation recommendation)
CFLAGS_vrfy.o := -O3
CFLAGS_fpr.o := -O3
