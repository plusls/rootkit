#ifndef ROOTKIT_HIDE_FILE_H
#define ROOTKIT_HIDE_FILE_H

bool hide_file_init(void);
void hide_file_exit(void);
bool hide_file(const char *file_name);
bool unhide_file(const char *file_name);

#endif