#ifndef _PTRACE_UTILS_H_
#define _PTRACE_UTILS_H_

#define CPSR_T_MASK     ( 1u << 5 )

int ptrace_attach( pid_t pid , int zygote);
int ptrace_detach( pid_t pid );

int ptrace_continue(pid_t pid);

int ptrace_syscall(pid_t pid);

int ptrace_getregs(pid_t pid, struct user_pt_regs* regs);
int ptrace_setregs(pid_t pid, struct user_pt_regs* regs);

int ptrace_write(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);
int ptrace_read( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size );

int show_regs(struct user_pt_regs* regs);
int show_mem(uint8_t *src,size_t size);

int ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct user_pt_regs* regs);

void* ptrace_dlopen(pid_t target_pid, void* remote_dlopen_addr, const char*  filename);


#endif