#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/reboot.h>

static char ret2bios_long[] = "crash";
static char ret2bios_real[] = "crash";
static char ret2bios_boot[] = "crash";

static int __init ret2bios_init(void)
{
    void *ret2long_loc;
    void *ret2real_loc;
    void *ret2boot_loc;
    void (*call_location)(void);

    migrate_to_reboot_cpu();

    ret2long_loc = xlate_dev_mem_ptr(0x10000);
    ret2real_loc = xlate_dev_mem_ptr(0x7e00);
    ret2boot_loc = xlate_dev_mem_ptr(0x7c00);

    memcpy(ret2long_loc, ret2bios_long, sizeof ret2bios_long);
    memcpy(ret2real_loc, ret2bios_real, sizeof ret2bios_real);
    memcpy(ret2boot_loc, ret2bios_boot, sizeof ret2bios_boot);

    call_location = (void (*)(void)) ret2long_loc;
    (*call_location)();

    // unreachable
    return 0;
}

static void __exit ret2bios_exit(void)
{
    // unreachable
}

module_init(ret2bios_init);
module_exit(ret2bios_exit);
