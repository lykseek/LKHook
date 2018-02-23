#ifndef _TOOL_H_
#define _TOOL_H_

#include <stdio.h>
#include <dlfcn.h>

void *get_method_address(const char *soname, const char *methodname);

const char* get_process_name(pid_t pid);

#endif