#ifndef ROOTKIT_HIDE_PID_H
#define ROOTKIT_HIDE_PID_H
#include <linux/types.h>
void hide_pid(pid_t pid);
void unhide_pid(pid_t pid_num);
void hide_pid_exit(void);
#endif
