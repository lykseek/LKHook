#include <stdio.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <elf.h>

#define DEBUG

#include "logger.h"
#include "ptrace_utils.h"


int show_regs(struct user_pt_regs* upr)
{
	int i;
	for (i=0;i<32;i++){
		if (i % 4 == 0)LOGI("\n");
		LOGI("X%02d: %08llx ",i,upr->regs[i]);		
	}

	LOGI("\nsp:%08llx pc:%08llx pstate:%08llx \n",upr->sp,upr->pc,upr->pstate);

	return 0;
}

int show_mem(uint8_t *src,size_t size)
{
	int i;
	LOGI("Mem start:");
	for (i=0; i<size; i++){
		if (i % 8 == 0)LOGI("\n");
		LOGI("%02x ",src[i]);
	}

	LOGI("\nMem end\n");

	return 0;
}



static void* connect_to_zygote(void* arg){
	int s, len;
	struct sockaddr_un remote;

	LOGI("[+] wait 2s...");
	sleep(2);

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) != -1) {
		remote.sun_family = AF_UNIX;
		strcpy(remote.sun_path, "/dev/socket/zygote");
		len = strlen(remote.sun_path) + sizeof(remote.sun_family);
		LOGI("[+] start to connect zygote socket");
		connect(s, (struct sockaddr *) &remote, len);
		LOGI("[+] close socket");
		close(s);
	}

	return NULL ;
}


/**
 * attach to target process
 */
int ptrace_attach(pid_t pid, int zygote) {
	if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
		LOGE("ptrace_attach");
		return -1;
	}

	pid_t wait_ret;

	LOGI("1 wait for attach...\n");
	wait_ret = waitpid(pid, NULL, WUNTRACED);
	LOGI("1 ret:%x \n",wait_ret);

	/*
	 * Restarts  the stopped child as for PTRACE_CONT, but arranges for
	 * the child to be stopped at the next entry to or exit from a sys‐
	 * tem  call,  or  after execution of a single instruction, respec‐
	 * tively.
	 */
	
	if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	LOGI("2 wait for syscall...\n");
	waitpid(pid, NULL, WUNTRACED);
	LOGI("2 ret:%x \n",wait_ret);
	/*
	if (zygote) {
		connect_to_zygote(NULL);
	}

	if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL ) < 0) {
		LOGE("ptrace_syscall");
		return -1;
	}

	LOGI("3 wait for ...\n");
	waitpid(pid, NULL, WUNTRACED);
	LOGI("3 ret:%x \n",wait_ret);
	*/

	return 0;
}

/**
 * detach from target process
 */
int ptrace_detach( pid_t pid )
{
    if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
    {
    	LOGE("ptrace_detach");
        return -1;
    }

    LOGI("[+] Detach success!\n");

    return 0;
}

int ptrace_continue(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
		LOGE("ptrace_cont");
		return -1;
	}

	return 0;
}

int ptrace_syscall(pid_t pid) {
	return ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}

/**
 * read registers' status
 * arch:arm64-v8a
 */
int ptrace_getregs(pid_t pid, struct user_pt_regs* regs)
{
	struct iovec ioVec = {0};

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);

	if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &ioVec) < 0) {
		perror("ptrace_getregs: Can not get register values");
		return -1;
	}

	return 0;
}

/**
 * set registers' status
 * arch:arm64-v8a
 */
int ptrace_setregs(pid_t pid, struct user_pt_regs* regs)
{
	struct iovec ioVec = {0};

	ioVec.iov_base = regs;
	ioVec.iov_len = sizeof(*regs);

	if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &ioVec) < 0) {
		perror("ptrace_setregs: Can not set register values");
		return -1;
	}

	return 0;
}

/**
 * write data to dest
 */
#define BYTES_WIDTH 8
int ptrace_write(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[BYTES_WIDTH];
	} d;

	j = size / BYTES_WIDTH;
	remain = size % BYTES_WIDTH;

	laddr = data;

	for (i = 0; i < j; i++) {
		memcpy(d.chars, laddr, BYTES_WIDTH);
		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

		dest += BYTES_WIDTH;
		laddr += BYTES_WIDTH;
	}

	if (remain > 0) {
		d.val = ptrace(PTRACE_PEEKTEXT, pid, (void *)dest, NULL);
		for (i = 0; i < remain; i++) {
			d.chars[i] = *laddr++;
		}

		ptrace(PTRACE_POKETEXT, pid, (void *)dest, (void *)d.val);

	}

	return 0;
}

int ptrace_read( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
    long i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[BYTES_WIDTH];
    } d;

    j = size / BYTES_WIDTH;
    remain = size % BYTES_WIDTH;

    laddr = buf;

    for ( i = 0; i < j; i ++ )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, BYTES_WIDTH);
        src += BYTES_WIDTH;
        laddr += BYTES_WIDTH;
    }

    if ( remain > 0 )
    {
        d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
        memcpy( laddr, d.chars, remain );
    }

    return 0;
}

#define NUM_PARAMS_REGISTERS 8
int ptrace_call(pid_t pid, uintptr_t addr, long *params, int num_params, struct user_pt_regs* pupr)
{
	int i;
	
	for (i=0; i < num_params && i < NUM_PARAMS_REGISTERS; i++)
	{
		pupr->regs[i] = params[i];
	}

	//push remained params onto stack
	if (i < num_params)
	{
		pupr->sp -= (num_params - i) * BYTES_WIDTH;
		ptrace_write(pid,(void*)pupr->sp,(uint8_t*)params[i],(num_params -i) * BYTES_WIDTH);		
	}

	pupr->pc = addr;
	if (pupr->pc & 1)
	{
		/*thumb*/
		pupr->pc &= (~1u);
		pupr->pstate |= CPSR_T_MASK;
	}else{
		/*arm*/
		pupr->pstate &= ~CPSR_T_MASK;
	}

	pupr->regs[30] = 0;

	if (ptrace_setregs(pid,pupr) == -1 || ptrace_continue(pid) == -1)
	{
		LOGI("[-] call error\n");
		return -1;
	}

	int stat = 0;
	pid_t wret = waitpid(pid,&stat,WUNTRACED);
	// LOGI("wait ret:%x,stat:%x\n",wret,stat);
	while(stat != 0xb7f){
		if(ptrace_continue(pid) == -1){
			LOGI("[-] call error \n");
			return -1;
		}

		waitpid(pid,&stat,WUNTRACED);
	}

	return 0;
}

void* ptrace_dlopen(pid_t target_pid, void* remote_dlopen_addr, const char*  filename){
	struct user_pt_regs regs;
	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL ;


	long mmap_params[2];
	size_t filename_len = strlen(filename) + 1;
	void* filename_addr = find_space_by_mmap(target_pid, 256) & 0x7fffffffff;

	if (filename_addr == NULL ) {
		LOGE("[-] Call Remote mmap fails.\n");
		return NULL ;
	}

	LOGI("[+] mmap addr:%p \n",filename_addr);

	ptrace_write(target_pid, (uint8_t *)filename_addr, (uint8_t *)filename, filename_len);

	mmap_params[0] = (long)filename_addr;  //filename pointer
	mmap_params[1] = RTLD_NOW | RTLD_GLOBAL; // flag

	// remote_dlopen_addr = (remote_dlopen_addr == NULL) ? get_remote_address(target_pid, (void *)dlopen) : remote_dlopen_addr;

	if (remote_dlopen_addr == NULL) {
		LOGE("[-] Get Remote dlopen address fails.\n");
		return NULL;
	}

	LOGI("[+] remote dlopen addr:%lx \n",remote_dlopen_addr);

	if (ptrace_call(target_pid, (uint64_t) remote_dlopen_addr, mmap_params, 2, &regs) == -1)
		return NULL;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return NULL;

	LOGI("[+] Target process returned from dlopen, return r0=%llx, r7=%llx, pc=%llx, \n", regs.regs[0] & 0x7fffffffff, regs.regs[7], regs.pc);

	return regs.pc == 0 ? (void *) regs.regs[0] : NULL;
}
