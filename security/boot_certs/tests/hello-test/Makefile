obj-m += hello.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Local keypair (generated once)

PRIVKEY ?= signing.key
PUBKEY  ?= Sheep_Signer.pem

# Kernel-provided signer tool (from headers/build dir)
SIGN_FILE ?= $(KDIR)/scripts/sign-file

all: modules sign

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules


sign: modules
	@test -x "$(SIGN_FILE)" || (echo "ERROR: $(SIGN_FILE) not found/executable. Install kernel headers/build tools."; exit 1)
	@echo "Signing hello.ko using kernel sign-file..."
	"$(SIGN_FILE)" sha3-512 "$(PRIVKEY)" "$(PUBKEY)" hello.ko
	@echo "Signed module info:"
	@modinfo hello.ko | egrep -i 'signer|sig_key|sig_hashalgo' || true

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all modules sign clean
