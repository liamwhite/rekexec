#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init ret2bios_init(void)
{
	printk(KERN_INFO "Ret2Bios\n");
	return 0;
}

static void __exit ret2bios_exit(void)
{
	// unreachable
}

module_init(ret2bios_init);
module_exit(ret2bios_exit);
