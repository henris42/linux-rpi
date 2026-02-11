# boot_certs_sysfs

Export a boot certificate chain via sysfs with strong immutability guarantees.

## What it does
- Reads `<boot>/certs/chain.pem` once at module load
- Verifies SHA3-512 hash against kernel cmdline
- Requires backing filesystem to be read-only
- Exposes cert as `/sys/kernel/boot_certs/chain.pem`
- Exposes `/sys/kernel/boot_certs/ok` (true|false)

## Build
```sh
make

make BOOT_MOUNT=firmware EXPECT_FSTYPE=vfat
make BOOT_MOUNT=boot EXPECT_FSTYPE=skip

## Booting

Linux boot needs a new argument:

boot_certs.sha3=<128 hex chars>

Create hash with:
openssl dgst -sha3-512 chain.pem


## Testing
sudo insmod boot_certs_sysfs.ko
cat /sys/kernel/boot_certs/ok

## creating csrs
openssl ecparam -out private.key -name secp384r1 -genkey
openssl req -new -key private.key -out server.csr