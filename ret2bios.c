#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <linux/kallsyms.h>

struct gdt_entry {
    u16 limit_low;
    u16 base_low;
    u8 base_middle;
    u8 access;
    u8 granularity;
    u8 base_high;
} __attribute__((packed));

struct gdt_ptr {
    u16 size;
    struct gdt_entry *base;
} __attribute__((packed));

struct gdt_ptr _gp;

static char ret2bios_real[] =
#include "ret2bios.h"
;

static u64 pt_walk_virt_to_phys(u64 virt_addr)
{
    u64 *pml4, *pdp, *pd, *pt;
    virt_addr &= 0xffffffffff000;
    asm volatile("mov %%cr3, %0" : "=r"(pml4));
    pml4 = (u64 *) phys_to_virt((u64)pml4 & 0xffffffffff000);
    pdp = (u64 *) phys_to_virt(pml4[(virt_addr >> 39) & 0x1ff] & 0xffffffffff000);
    pd = (u64 *) phys_to_virt(pdp[(virt_addr >> 30) & 0x1ff] & 0xffffffffff000);
    pt = (u64 *) phys_to_virt(pd[(virt_addr >> 21) & 0x1ff] & 0xffffffffff000);
    return pt[(virt_addr >> 12) & 0x1ff] & 0xffffffffff000;
}

static int __init ret2bios_init(void)
{
    void (*kernel_restart_prepare)(char *);
    void (*migrate_to_reboot_cpu)(void);
    void (*disable_IO_APIC)(void);
    u16 exec_segment;

    kernel_restart_prepare = (void (*)(char *)) kallsyms_lookup_name("kernel_restart_prepare");
    migrate_to_reboot_cpu = (void (*)(void)) kallsyms_lookup_name("migrate_to_reboot_cpu");
    disable_IO_APIC = (void (*)(void)) kallsyms_lookup_name("disable_IO_APIC");

    (*kernel_restart_prepare)(NULL);
    (*migrate_to_reboot_cpu)();
    (*disable_IO_APIC)();

    // Hijack the GDT
    asm volatile(
        "sgdt _gp(%rip)\n\t"
    );

    exec_segment = ((_gp.size + 1) / 8) - 1;

    _gp.base[exec_segment] = ((struct gdt_entry) {
        .limit_low = 0xffff,
        .base_low = 0x0,
        .base_middle = 0x0,
        .access = 0b10011110,
        .granularity = 0b11001111,
        .base_high = 0x0
    });

    // write our code
    memcpy(phys_to_virt(0x7e00), ret2bios_real, sizeof(ret2bios_real));

    u64 cr3;

    u64 *newpml4 = (u64 *) phys_to_virt(0x10000);
    u64 *newpdp  = (u64 *) phys_to_virt(0x11000);
    u64 *newpd   = (u64 *) phys_to_virt(0x12000);
    u64 *newpt   = (u64 *) phys_to_virt(0x13000);

    memset(newpml4, 0x0, 0x4000);

    // map this code page
    u64 virt_code = (u64) &ret2bios_init;
    u64 phys_code = pt_walk_virt_to_phys(virt_code);

    newpml4[(virt_code >> 39) & 0x1ff] = (u64) ((virt_to_phys(newpdp) & 0xffffffffff000) | 0x1);
    newpdp[(virt_code >> 30) & 0x1ff]  = (u64) ((virt_to_phys(newpd) & 0xffffffffff000) | 0x1);
    newpd[(virt_code >> 21) & 0x1ff]   = (u64) ((virt_to_phys(newpt) & 0xffffffffff000) | 0x1);
    newpt[(virt_code >> 12) & 0x1ff]   = (u64) ((phys_code & 0xffffffffff000) | 0x1);

    // map the 0x7000 page to itself
    newpml4[0] = (u64) ((virt_to_phys(newpdp) & 0xffffffffff000) | 0x1);
    newpdp[0]  = (u64) ((virt_to_phys(newpd) & 0xffffffffff000) | 0x1);
    newpd[0]   = (u64) ((virt_to_phys(newpt) & 0xffffffffff000) | 0x1);
    newpt[7]   = (u64) ((0x7000 & 0xffffffffff000) | 0x1);

    cr3 = ((u64) virt_to_phys(newpml4)) & 0xffffffffff000;

    asm volatile(
        "cli\n\t"
        "mov %0, %%cr3\n\t"
        "mov %1, %%fs\n\t"
        "push %%fs\n\t"
        "push $0x7e00\n\t"
        "retfq\n\t"
        : : "r"(cr3), "r"(exec_segment * 8)
    );

    // unreachable
    return 0;
}

static void __exit ret2bios_exit(void)
{
    // unreachable
}

module_init(ret2bios_init);
module_exit(ret2bios_exit);

MODULE_LICENSE("GPL");
