/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <signal.h>

#include <capstone/capstone.h>

#define MAX_LENGTH 100
#define MAX_BREAKPOINTS 100
#define TOOL "mdb"
		
#define die(...) \
    do { \
        fprintf(stderr, TOOL": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)
		
#define DIE(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

Elf *elf;
Elf_Scn *symtab; 
csh handle;
//Elf_Data *data = NULL;
int flag = 0; //using it to beautify the output of the disas

void disas_op(const unsigned char *buffer,int len, long addr) { //function that implements disas
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, buffer, len, addr, 0, &insn);

    if (count > 0) {
		size_t j;
		for (j = 0; j < 11 && j < count; j++) {
			if (flag == 0){
				fprintf(stderr, "=> 0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
						insn[j].op_str);
				flag = 1;
			}else{
				fprintf(stderr, "   0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
						insn[j].op_str);
			}
		}
		cs_free(insn, count);
	} else
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
	flag = 0;
}

void long_to_str(long ins, char *str) { //used to transform the current instruction
    char *bytes = (char *)&ins;
    int len = sizeof(long);
    for (int i = 0; i < len; i++) {
        sprintf(str + (i*4), "\\x%02x", (unsigned char)bytes[i]);
    }
}

void process_inspect(int pid) {	//function that collects the arguments for the disas function
    struct user_regs_struct regs;
	char str_ins[40] = {0};

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("%s", strerror(errno));
  
    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0); //find current instruction
    if (current_ins == -1) 
        die("(peekdata) %s", strerror(errno));
	
	long_to_str(current_ins, str_ins);
	const unsigned char * code = (unsigned char *) str_ins; //transform current instruction
	disas_op(code,strlen(str_ins),regs.rip); //call the function that implements disas
 
}

long set_breakpoint(int pid, long addr) {	//function that sets breakpoints
    /* Backup current code.  */
    long previous_code = 0; 
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (previous_code == -1)
        die("(peekdata) %s", strerror(errno));
	

	/* Insert the breakpoint. */
	long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
	if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
		die("(pokedata) %s", strerror(errno));
	
    return previous_code; 
}

void process_step(int pid) {	//function that implements si

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)	//do a single step
        die("(singlestep) %s", strerror(errno)); 
 
    waitpid(pid, 0, 0); 
	
}

void serve_breakpoint(int pid, long original_instruction, long addr) {	//function that removes breakpoints
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
            die("(getregs) %s", strerror(errno));
  
	
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)original_instruction)  == -1)
        die("(pokedata) %s", strerror(errno));
    
	process_step(pid);

}

/*void disas(const unsigned char *buffer, unsigned int size, long addr,int pid) {
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, buffer, size - addr, addr, 0, &insn);

    if (count > 0) {
		size_t j;
		for (j = 0; j < 11 && j<count; j++) {
			fprintf(stderr, "0x%"PRIx64":\t%s\t\t%s\n", insn[j].address-1, insn[j].mnemonic,
					insn[j].op_str);
		}
		cs_free(insn, count);
	} else
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}*/

long find_symbol(Elf *elf, Elf_Scn *scn, char *filename, char *symbolname){	//function that finds symbol in the symboltable and returns its address
	Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;
	char symbol_name[MAX_LENGTH];
	int flag_sym;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize;
	
	for (int i = 0; i < count; ++i) {
			GElf_Sym sym;
			gelf_getsym(data, i, &sym);
			strcpy(symbol_name, elf_strptr(elf, shdr.sh_link, sym.st_name));
			flag_sym = 1;
			if (strncmp(symbol_name,symbolname,strlen(symbolname)-1)){	//if this is the symbol you are looking for
				flag_sym =0;
			}
			if ( flag_sym == 1 ){	//return its address
				return sym.st_value;	
			}
	}
	return -1;
}

void load_file(char *filename, csh handle) {
	
    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));
		
	int s_index = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        s_index++;
		
        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")){
            symtab = scn;
		}
		
		/* Locate .text  
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text")) {
			data = elf_getdata(scn, data);
        }*/
    }
}

int main(int argc, char **argv)
{
	char c[MAX_LENGTH];	//using it for reading the commands
	long addr;
	long brp[MAX_BREAKPOINTS];	//list for breakpoints
	long or_inst[MAX_BREAKPOINTS];	//list for the original instructions in the breakpoints
	int count = 0;	//counting breakpoints
	long original_instruction;
	int br_num;
	int runned = 0;	//checking if the programm is runned before entering c command
	
	for (int i =0;i<MAX_BREAKPOINTS;i++){	//initialize the lists
		brp[i]=-1;
		or_inst[i]=-1;
	}
	
	/* Initialize the engine.  */
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
	
    if (argc <= 1)
        die("mdb <program>: %d", argc);
	
	load_file(argv[1],handle);

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            die("%s", strerror(errno));
        case 0:  /* Code that is run by the child. */
            /* Start tracing.  */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp() is a system call, the child will block and
               the parent must do waitpid().
               The waitpid() of the parent is in the label
               waitpid_for_execvp.
             */
            execvp(argv[1], argv + 1);
            die("%s", strerror(errno));
    }
	
	/* Code that is run by the parent.  */
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
	waitpid(pid, 0, 0);
	
	//struct user_regs_struct regs;

	while ( c[0] != 'q')	//exit with q command
	{
		fgets(c, sizeof(c), stdin);
		
		
		if (c[0] == 'r' ){	//run
			struct user_regs_struct regs;
			fprintf(stderr, "Running.\n");
			runned = 1;
			
			if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)	//run the program
			   die("(cont) %s", strerror(errno));
			
			int status;
			
			waitpid(pid, &status, 0);
			
			if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {	//if you hit a breakpoint
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
					die("%s", strerror(errno));
				
				long rip = regs.rip;
				printf("Breakpoint hit at address 0x%lx.\n",rip-1);	//print its address
				process_inspect(pid);	//print disassembly
			}
			if (WIFEXITED(status)) {	//exit if the execution finished
				break;
			}
			if (WIFSTOPPED(status) == 1 && WSTOPSIG(status) == 11) {
				break;
			}
			
			
		}else if(c[0] == 'b'){	//add breakpoint
			
			if (c[2] == '*'){	//read the given address
				memmove(c, c + 1, strlen(c));
				c[0] = '0';
				c[1] = 'x';
				addr = strtol(c, NULL, 16);
			} else {	//read the given symbol name
				memmove(c, c + 2, strlen(c)-1);
				addr = find_symbol(elf, symtab,argv[1],c);	//find the address of the symbol
			}
			
			if (addr == -1){
				printf("There is not this symbol.\n");	//print the message if there is not the given symbol
			}else {
				original_instruction = set_breakpoint(pid, addr);	//add the breakpoint
				or_inst[count] = original_instruction;	//save the original instruction
				brp [count] = addr;	//save the breakpoint
				count += 1;
				printf("Breakpoint %x added at 0x%lx.\n" ,count,brp[count-1]);
			}
			
			
		}else if(c[0] == 'l'){	//print breakpoints list
			int flag_list = 0;	//flag for existance of breakpoints
			
			for (int i = 0; i < count; i++) {
				if ( brp[i] != -1){
					printf("Breakpoint %x at 0x%lx.\n" ,i+1,brp[i]);	//print breakpoints with their number and address
					flag_list = 1;
				}
			}
			
			if (flag_list == 0){
				fprintf(stderr, "There are not any Breakpoints.\n");
			}
			flag_list = 0;
		
		
		}else if(c[0] == 'd' && c[1] == 'i' && c[2] == 's' && c[3] == 'a' && c[4] == 's'){	//disas
			process_inspect(pid);	//print disassembly
		
		
		}else if(c[0] == 'd'){	//delete
			br_num = atoi(&c[2]);	//read the number of breakpoint
			
			if (brp[br_num-1] == -1){	//if there is not this breakpoint
				printf("There is not Breakpoint with number %d.\n",br_num);	//print message
			}else{
				serve_breakpoint(pid,or_inst[br_num-1],brp[br_num-1]);	//delete breakpoint
				brp[br_num-1] = -1;	//release breakpoints list
				or_inst[br_num-1] = -1;	//release original instructions list
				printf("Breakpoint with number %x is deleted.\n",br_num);
			}
			
			
		}else if(c[0] == 'c'){	//continue
			struct user_regs_struct regs;
				
			if (runned == 0){	//check if the program is runned
				fprintf(stderr, "The program is not being run.\n");
			}else{	
				fprintf(stderr, "Continuing.\n");
				if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)	//continue the execution
				   die("(cont) %s", strerror(errno));
				
				int status;
				
				waitpid(pid, &status, 0);
					
				if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {	//if you hit a breakpoint
					if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
						die("%s", strerror(errno));
					
					long rip = regs.rip;
					printf("Breakpoint hit at address 0x%lx.\n",rip-1);	//print the breakpoint with number and address
				}
				if (WIFEXITED(status)) {	//exit if the execution finished
					break;
				}
				if (WIFSTOPPED(status) == 1 && WSTOPSIG(status) == 11) {
					break;
				}
			}
		
		
		}else if(c[0] == 's' && c[1] == 'i'){	//si
			struct user_regs_struct regs;
			process_step(pid);	//do singlestep
			
			if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) 
				die("%s", strerror(errno));
   
			fprintf(stderr, "=> 0x%llx \n", regs.rip);	//print current address
			
			
		}else if (c[0] != 'q'){	//unknown command
			fprintf(stderr, "Not supported command.\n");
		}
	}
	cs_close(&handle);
}
