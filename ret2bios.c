#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>

// Kernel hijack code

struct kernel_setup {
  char *kernel_buffer;
  size_t kernel_buffer_sz;
  char *kernel_cmdline;
  size_t kernel_cmdline_sz;
  char *initrd_buffer;
  size_t initrd_buffer_sz;
};

static struct kernel_setup ks = { 0 };

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

static void ret2bios(void)
{
    void (*kernel_restart_prepare)(char *);
    void (*migrate_to_reboot_cpu)(void);
    void (*disable_IO_APIC)(void);
    u16 exec_segment;
    u64 cr3, virt_code, phys_code;
    u64 *newpml4, *newpdp, *newpd, *newpt;

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

    newpml4 = (u64 *) phys_to_virt(0x10000);
    newpdp  = (u64 *) phys_to_virt(0x11000);
    newpd   = (u64 *) phys_to_virt(0x12000);
    newpt   = (u64 *) phys_to_virt(0x13000);

    memset(newpml4, 0x0, 0x4000);

    // map this code page
    virt_code = (u64) &ret2bios;
    phys_code = pt_walk_virt_to_phys(virt_code);

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
        "push %2\n\t"
        "push %%fs\n\t"
        "push $0x7e00\n\t"
        "retfq\n\t"
        : : "r"(cr3), "r"(exec_segment * 8), "r"(virt_to_phys(&ks))
    );
}


// Kernel device code

static unsigned int major;

static ssize_t kexec_read_minor_dispatch(struct file *filp, char *buf, size_t len, loff_t *off);
static ssize_t kexec_write_minor_dispatch(struct file *filp, const char *buf, size_t len, loff_t *off);

static ssize_t kernel_buffer_read(struct file *, char *, size_t, loff_t *);
static ssize_t kernel_buffer_write(struct file *, const char *, size_t, loff_t *);
static ssize_t kernel_cmdline_read(struct file *, char *, size_t, loff_t *);
static ssize_t kernel_cmdline_write(struct file *, const char *, size_t, loff_t *);
static ssize_t initrd_buffer_read(struct file *, char *, size_t, loff_t *);
static ssize_t initrd_buffer_write(struct file *, const char *, size_t, loff_t *);
static ssize_t kexec_run_read(struct file *, char *, size_t, loff_t *);
static ssize_t kexec_run_write(struct file *, const char *, size_t, loff_t *);

// minor 0
static struct class *kexec_kernel_class   = NULL;
static struct device *kexec_kernel_device = NULL;

// minor 1
static struct class *kexec_cmdline_class   = NULL;
static struct device *kexec_cmdline_device = NULL;

// minor 2
static struct class *kexec_initrd_class   = NULL;
static struct device *kexec_initrd_device = NULL;

// minor 3
static struct class *kexec_run_class   = NULL;
static struct device *kexec_run_device = NULL;

struct file_operations ret2bios_fops = {
    .read = kexec_read_minor_dispatch,
    .write = kexec_write_minor_dispatch,
};

static int __init ret2bios_init(void)
{
    ret2bios_fops.owner = THIS_MODULE;

    // 20MB max kernel, 1k max cmdline, 50MB max initrd
    ks.kernel_buffer = kmalloc(20000000, GFP_KERNEL);
    ks.kernel_cmdline = kmalloc(1000, GFP_KERNEL);
    ks.initrd_buffer = kmalloc(50000000, GFP_KERNEL);

    major = register_chrdev(0, "ret2bios", &ret2bios_fops);
    kexec_kernel_class = class_create(THIS_MODULE, "kexec_kernel");
    kexec_cmdline_class = class_create(THIS_MODULE, "kexec_cmdline");
    kexec_initrd_class = class_create(THIS_MODULE, "kexec_initrd");
    kexec_run_class = class_create(THIS_MODULE, "kexec_run");
    kexec_kernel_device = device_create(kexec_kernel_class, NULL, MKDEV(major, 0), NULL, "kexec_kernel");
    kexec_cmdline_device = device_create(kexec_cmdline_class, NULL, MKDEV(major, 1), NULL, "kexec_cmdline");
    kexec_initrd_device = device_create(kexec_initrd_class, NULL, MKDEV(major, 2), NULL, "kexec_initrd");
    kexec_run_device = device_create(kexec_run_class, NULL, MKDEV(major, 3), NULL, "kexec_run");

    return 0;
}
// This is silly. Why do we care if we leak?
static void __exit ret2bios_exit(void)
{
    device_destroy(kexec_run_class, MKDEV(major, 3));
    device_destroy(kexec_initrd_class, MKDEV(major, 2));
    device_destroy(kexec_cmdline_class, MKDEV(major, 1));
    device_destroy(kexec_kernel_class, MKDEV(major, 0));
    class_unregister(kexec_run_class);
    class_unregister(kexec_initrd_class);
    class_unregister(kexec_cmdline_class);
    class_unregister(kexec_kernel_class);
    class_destroy(kexec_run_class);
    class_destroy(kexec_initrd_class);
    class_destroy(kexec_cmdline_class);
    class_destroy(kexec_kernel_class);
    unregister_chrdev(major, "ret2bios");
    kfree(ks.kernel_buffer);
    kfree(ks.kernel_cmdline);
    kfree(ks.initrd_buffer);
}


#define MAX(a,b) (((a)>(b))?(a):(b))

static ssize_t kexec_read_minor_dispatch(struct file *filp, char *buf, size_t len, loff_t *off)
{
    switch (iminor(filp->f_path.dentry->d_inode)) {
    case 0:
        return kernel_buffer_read(filp, buf, len, off);
    case 1:
        return kernel_cmdline_read(filp, buf, len, off);
    case 2:
        return initrd_buffer_read(filp, buf, len, off);
    }

    return kexec_run_read(filp, buf, len, off);
}

static ssize_t kexec_write_minor_dispatch(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    switch (iminor(filp->f_path.dentry->d_inode)) {
    case 0:
        return kernel_buffer_write(filp, buf, len, off);
    case 1:
        return kernel_cmdline_write(filp, buf, len, off);
    case 2:
        return initrd_buffer_write(filp, buf, len, off);
    }

    return kexec_run_write(filp, buf, len, off);
}

static ssize_t kernel_buffer_read(struct file *filp, char *buf, size_t len, loff_t *off)
{
    if (*off + len > ks.kernel_buffer_sz)
        return -EFAULT;

    copy_to_user(buf, ks.kernel_buffer + *off, len);
    *off += len;

    return len;
}

static ssize_t kernel_buffer_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    if (*off + len >= 20000000)
        return -EFAULT;

    ks.kernel_buffer_sz = MAX(ks.kernel_buffer_sz, *off + len);
    copy_from_user(ks.kernel_buffer + *off, buf, len);
    *off += len;

    return len;
}

static ssize_t kernel_cmdline_read(struct file *filp, char *buf, size_t len, loff_t *off)
{
    if (*off + len > ks.kernel_cmdline_sz)
        return -EFAULT;

    copy_to_user(buf, ks.kernel_cmdline + *off, len);
    *off += len;

    return len;
}

static ssize_t kernel_cmdline_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    if (*off + len >= 1000)
        return -EFAULT;

    ks.kernel_cmdline_sz = MAX(ks.kernel_cmdline_sz, *off + len);
    copy_from_user(ks.kernel_cmdline + *off, buf, len);
    *off += len;

    return len;
}

static ssize_t initrd_buffer_read(struct file *filp, char *buf, size_t len, loff_t *off)
{
    if (*off + len > ks.initrd_buffer_sz)
        return -EFAULT;

    copy_to_user(buf, ks.initrd_buffer + *off, len);
    *off += len;

    return len;
}

static ssize_t initrd_buffer_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    if (*off + len >= 50000000)
        return -EFAULT;

    ks.kernel_cmdline_sz = MAX(ks.kernel_cmdline_sz, *off + len);
    copy_from_user(ks.initrd_buffer + *off, buf, len);
    *off += len;

    return len;
}

static ssize_t kexec_run_read(struct file *filp, char *buf, size_t len, loff_t *off)
{
    if (*off > 0)
        return -EFAULT;

    copy_to_user(buf, "0", 1);
    *off += 1;

    return 1;
}

static ssize_t kexec_run_write(struct file *filp, const char *buf, size_t len, loff_t *off)
{
    ret2bios();

    // unreachable
    return 0;
}

module_init(ret2bios_init);
module_exit(ret2bios_exit);

MODULE_LICENSE("GPL");
