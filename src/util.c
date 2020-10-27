#include <linux/kernel.h>
#include <linux/slab.h>

#include "util.h"

inline void mywrite_cr0(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0"
                 : "+r"(cr0), "+m"(__force_order));
}

void enable_wp(void)
{
    // 可能存在条件竞争
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();

    return;
}

void disable_wp(void)
{
    // 可能存在条件竞争
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();

    return;
}

void hook_and_save(void *base, size_t offset, void *new_ptr, void **old_ptr)
{
    // 保存旧值
    if (old_ptr)
    {
        *old_ptr = *(void **)((char *)base + offset);
        fm_info("Save old_ptr: %p\n", *old_ptr);
    }

    fm_info("Changing %p->%p to %p.\n", base, (void *)offset, new_ptr);
    disable_wp();
    *(void **)((char *)base + offset) = new_ptr;
    enable_wp();
}