#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <elf.h>

#define DEBUG

#include "tools.h"
#include "elf_utils.h"
#include "ptrace_utils.h"
#include "logger.h"

void* get_module_base(pid_t pid, const char* module_name) {
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if (pid < 0) {
		/* self process */
		snprintf(filename, sizeof(filename), "/proc/self/maps");
	} else {
		snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	}

	fp = fopen(filename, "r");

	if (fp != NULL) {
		while (fgets(line, sizeof(line), fp)) {

			if (strstr(line, module_name)) {
				pch = strtok(line, "-");
				addr = strtoul(pch, NULL, 16);

				if (addr == 0x8000)
					addr = 0;

				break;
			}
		}

		fclose(fp);
	}

	return (void *) addr;
}

void* find_space_by_mmap(pid_t target_pid, int size) {
	struct user_pt_regs regs;
	if (ptrace_getregs(target_pid, &regs) == -1)
		return 0;

	long parameters[10];

	/* call mmap */
	parameters[0] = 0;  // addr
	parameters[1] = size; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset

	void *remote_mmap_addr = get_remote_address(target_pid, get_method_address("/system/lib64/libc.so", "mmap"));
	LOGI("[+] Calling mmap in target process. mmap addr %p.\n", remote_mmap_addr);

	if (remote_mmap_addr == NULL) {
		LOGE("[-] Get Remote mmap address fails.\n");
		return 0;
	}

	if (ptrace_call(target_pid, (uint64_t) remote_mmap_addr, parameters, 6, &regs) == -1)
		return 0;

	if (ptrace_getregs(target_pid, &regs) == -1)
		return 0;

	LOGI("[+] Target process returned from mmap, return r0=%llx, r7=%llx, pc=%llx, \n", regs.regs[0], regs.regs[7], regs.pc);

	return regs.pc == 0 ? (void *) regs.regs[0] : 0;
}

static char* nexttok(char **strp) {
	char *p = strsep(strp, " ");
	return p == NULL ? "" : p;
}

void* find_space_in_maps(pid_t pid, int size) {
	char statline[1024];
	FILE * fp;
	uint64_t* addr = (uint64_t*) 0x40008000;
	char *address, *proms, *ptr;
	const char* tname = "/system/lib64/libc.so";
	const char* tproms = "r-xp";
	int tnaem_size = strlen(tname);
	int tproms_size = strlen(tproms);

	size = ((size / 8) + 1) * 8;

	sprintf(statline, "/proc/%d/maps", pid);

	fp = fopen(statline, "r");
	if (fp == 0)
		return 0;

	while (fgets(statline, sizeof(statline), fp)) {
		ptr = statline;
		address = nexttok(&ptr); // skip address
		proms = nexttok(&ptr); // skip proms
		nexttok(&ptr); // skip offset
		nexttok(&ptr); // skip dev
		nexttok(&ptr); // skip inode

		while (*ptr != '\0') {
			if (*ptr == ' ')
				ptr++;
			else
				break;
		}

		if (ptr && proms && address) {
			if (strncmp(tproms, proms, tproms_size) == 0) {
				if (strncmp(tname, ptr, tnaem_size) == 0) {
					// address like 7f8e29b000-7f8e2a0000
					if (strlen(address) == 21) {
						addr = (uint64_t*) strtoul(address + 11, NULL, 16);
						addr -= size;
						printf("proms=%s address=%s name=%s", proms, address,
								ptr);
						break;
					}
				}
			}
		}
	}

	fclose(fp);
	return (void*) addr;
}

int find_module_info_by_address(pid_t pid, void* addr, char *module, void** start, void** end) {
	char statline[1024];
	FILE *fp;
	char *address, *proms, *ptr, *p;

	if ( pid < 0 ) {
		/* self process */
		snprintf( statline, sizeof(statline), "/proc/self/maps");
	} else {
		snprintf( statline, sizeof(statline), "/proc/%d/maps", pid );
	}

	fp = fopen( statline, "r" );

	if ( fp != NULL ) {
		while ( fgets( statline, sizeof(statline), fp ) ) {
			ptr = statline;
			address = nexttok(&ptr); // skip address
			proms = nexttok(&ptr); // skip proms
			nexttok(&ptr); // skip offset
			nexttok(&ptr); // skip dev
			nexttok(&ptr); // skip inode

			while(*ptr != '\0') {
				if(*ptr == ' ')
					ptr++;
				else
					break;
			}

			p = ptr;
			while(*p != '\0') {
				if(*p == '\n')
					*p = '\0';
				p++;
			}

			//7f8e5bf000-7f8e5c0000
			if(strlen(address) == 21) {
				address[10] = '\0';

				*start = (void*)strtoul(address, NULL, 16);
				*end   = (void*)strtoul(address+11, NULL, 16);

				// LOGI("[%p-%p] %s | %p\n", *start, *end, ptr, addr);

				if(addr > *start && addr < *end) {
					strcpy(module, ptr);

					fclose( fp ) ;
					return 0;
				}
			}
		}

		fclose( fp ) ;
	}

	return -1;
}

int find_module_info_by_name(pid_t pid, const char *module, void** start, void** end) {
	char statline[1024];
	FILE *fp;
	char *address, *proms, *ptr, *p;

	if ( pid < 0 ) {
		/* self process */
		snprintf( statline, sizeof(statline), "/proc/self/maps");
	} else {
		snprintf( statline, sizeof(statline), "/proc/%d/maps", pid );
	}

	fp = fopen( statline, "r" );

	if ( fp != NULL ) {
		while ( fgets( statline, sizeof(statline), fp ) ) {
			ptr = statline;
			address = nexttok(&ptr); // skip address
			proms = nexttok(&ptr); // skip proms
			nexttok(&ptr); // skip offset
			nexttok(&ptr); // skip dev
			nexttok(&ptr); // skip inode

			while(*ptr != '\0') {
				if(*ptr == ' ')
					ptr++;
				else
					break;
			}

			p = ptr;
			while(*p != '\0') {
				if(*p == '\n')
					*p = '\0';
				p++;
			}

			//7f8e5bf000-7f8e5c0000
			if(strlen(address) == 21) {
				address[10] = '\0';

				*start = (void*)strtoul(address, NULL, 16);
				*end   = (void*)strtoul(address+11, NULL, 16);

				// LOGI("[%p-%p] %s \n", *start, *end, ptr);

				if(strncmp(module, ptr, strlen(module)) == 0) {
					fclose( fp ) ;
					return 0;
				}
			}
		}

		fclose( fp ) ;
	}

	return -1;
}

void* get_remote_address(pid_t pid, void *local_addr) {
	char buf[256];
	void* local_start = 0;
	void* local_end = 0;
	void* remote_start = 0;
	void* remote_end = 0;

	if(find_module_info_by_address(-1, local_addr, buf, &local_start, &local_end) < 0) {
		LOGI("[-] find_module_info_by_address FAIL");
		return NULL;
	}

	LOGI("[+] the local module is %s\n", buf);

	if(find_module_info_by_name(pid, buf, &remote_start, &remote_end) < 0) {
		LOGI("[-] find_module_info_by_name FAIL");
		return NULL;
	}

	LOGI("[+] the remote module is %s\n", buf);

	// LOGI("local_addr:%lx,local_start:%lx,remote_start:%lx \n",local_addr,local_start,remote_start);	

	uint64_t remote = (uint64_t)local_addr - (uint64_t)local_start + (uint64_t)remote_start;

	// LOGI("remote:%lx\n",remote);

	return (void*)remote ;
}


