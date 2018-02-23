#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

//debug is on
#define DEBUG
//debug is android log
//#define _ANDROID_

#include "logger.h"
#include "ptrace_utils.h"
#include "tools.h"


#define USAGE "usage:\n inject pid /absolutepath/xxx.so  \n"

struct process_inject {
	pid_t 		pid;
	char 		*dso;
//	void		*dlopen_addr;
//	void 		*dlsym_addr;
//	void		*mmap_addr;
} process_inject = {0, "" /*NULL, NULL, NULL*/};


int main(int argc,char *argv[])
{	
	if (argc < 2){
		LOGI(USAGE);
		exit(0);
	}

	process_inject.pid = atoi(argv[1]);
	process_inject.dso = strdup(argv[2]);	

	LOGI("Try to inject to %d with %s\n",process_inject.pid,process_inject.dso);

	if (access(process_inject.dso, R_OK|X_OK) < 0) {
		LOGE("[-] so file must chmod rx\n");
		exit(1);
	}

	const char* process_name = get_process_name(process_inject.pid);
	int zygote = (int)strstr(process_name,"zygote");

	LOGI("[+] Try Attach %s ,%d ,zygote:%d\n",process_name,process_inject.pid,zygote);
	ptrace_attach(process_inject.pid,zygote);
	LOGI("[+] Attach Success!\n");

	struct user_pt_regs upr={0};
	if (ptrace_getregs(process_inject.pid,&upr) < 0)
	{
		LOGE("[-] Can't get reg values !\n");
		goto DETACH;
	}
	LOGI("[+] pc: %llx, LR: %lx\n", upr.pc, upr.regs[30]);

	/*some test*/
	/*
	struct user_pt_regs upr={0};
	ptrace_getregs(process_inject.pid,&upr);
	show_regs(&upr); 
	ptrace_setregs(process_inject.pid,&upr);

	uint8_t buffer[32]={0};
	ptrace_read(process_inject.pid,upr.pc,buffer,32);
	show_mem(buffer,32);
	ptrace_write(process_inject.pid,upr.pc,buffer,32);
	*/
	// &0x7fffffffff maybe a bug
	// void* remote_dlsym_addr = get_remote_address(process_inject.pid, (void *)dlsym) & 0x7fffffffff;
	void* remote_dlopen_addr =  get_remote_address(process_inject.pid, (void *)dlopen) & 0x7fffffffff;

	// LOGI("[+] remote_dlsym_addr:%lx,remote_dlopen_addr:%lx \n",remote_dlsym_addr,remote_dlopen_addr);

	if(ptrace_dlopen(process_inject.pid, remote_dlopen_addr, process_inject.dso) == NULL){
		LOGE("[-] Ptrace dlopen fail. %s\n", dlerror());
	}	

	if (ptrace_setregs(process_inject.pid, &upr) == -1) {
		LOGE("[-] Set regs fail. %s\n", strerror(errno));
		goto DETACH;
	}

	LOGI("[+] Inject success!\n");


DETACH:
	ptrace_detach(process_inject.pid);
	LOGI("[+] Inject done!\n");

	return 0;
}