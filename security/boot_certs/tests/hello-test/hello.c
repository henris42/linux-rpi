#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init hello_init(void)
{
    pr_info("hello_kmod: Hello, kernel log!\n");
    return 0;
}

static void __exit hello_exit(void)
{
    pr_info("hello_kmod: Goodbye, kernel log!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("Simple hello world kernel module (signed)");
MODULE_VERSION("1.0");
