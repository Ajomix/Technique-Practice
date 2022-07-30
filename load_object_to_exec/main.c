#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>

typedef union {
    const Elf64_Ehdr *hdr;
    const uint8_t *base;
} objhdr;
static uint64_t page_size;

uint64_t page_align(uint64_t n)
{
    return (n + (page_size - 1)) & ~(page_size - 1);
}

static objhdr obj;
static Elf64_Shdr *sections;
static const char *shstrtab = NULL;


void load_object(){
	
	struct stat st;

	int fs = open("simple.o",O_RDONLY);
	if(fs <= 0){
		perror("failed to open object file (*.o)");
		exit(errno);
	}
	if(fstat(fs,&st) == -1){
		perror("failed to get status of file object");
		exit(errno);
	}
	obj.base = mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fs,0);
	if (obj.base == MAP_FAILED){
		perror("Failed to mmap ");
		exit(errno);
	}
 	sections = (Elf64_Shdr*)(obj.base + obj.hdr->e_shoff);
 	shstrtab = (const char *)(obj.base + sections[obj.hdr->e_shstrndx].sh_offset);

	close(fs);
}

Elf64_Shdr *lookup_section(unsigned char * name){

	int len_input = strlen(name); 

	for(int i=1;i<obj.hdr->e_shnum;i++){
		unsigned char *name_section = (unsigned char*)(shstrtab + sections[i].sh_name);
		if(!strcmp(name,name_section) && len_input == strlen(name_section))
			return &sections[i];
	}
	return NULL;
}

static Elf64_Sym *symbol_table;
static uint64_t nsymbol; 
static unsigned char *strtab;
static uint8_t *base_runtime_text;
void parse_object(){
	Elf64_Shdr *symtab = lookup_section(".symtab");
	if(symtab == NULL){
		perror("Failed to look up .symtab");
		exit(errno);
	}
	//symbol table 
	symbol_table = (Elf64_Sym*)(obj.base + symtab->sh_offset);
	nsymbol = symtab->sh_size / symtab->sh_entsize;

	page_size = sysconf(_SC_PAGESIZE);

	
	Elf64_Shdr *strtab_hdr = lookup_section(".strtab");
	strtab = (unsigned char *)(obj.base + strtab_hdr->sh_offset);

	Elf64_Shdr* text_section = lookup_section(".text");
	uint64_t base_text_section = (uint64_t)(obj.base + text_section->sh_offset);

	base_runtime_text = mmap(NULL,page_align(text_section->sh_size),PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	if(base_runtime_text == MAP_FAILED){
		perror("Failed to map text section");
		exit(errno);
	}
	memcpy(base_runtime_text,(void*)base_text_section,text_section->sh_size);

	if(mprotect(base_runtime_text,page_align(text_section->sh_size),PROT_EXEC|PROT_READ)){
		perror("Failed to protect memory of text section");
		exit(errno);
	}

}
void *lookup_function(unsigned char *name){
	uint8_t len_input = strlen(name);
	unsigned char *name_symbol;
	
	for(int i=0;i<nsymbol;i++){
		name_symbol = (unsigned char*)&strtab[symbol_table[i].st_name];
		//printf("%s\n",name_symbol);
		if( ELF64_ST_TYPE(symbol_table[i].st_info) == STT_FUNC && 
			!strcmp(name_symbol,name)&&
			len_input == strlen(name_symbol)){
			return (base_runtime_text + symbol_table[i].st_value);

		}
	}
	return NULL;
}
void execute_fucntion(){
	int(*add5)(int);
	int(*add10)(int);
	add5 = lookup_function("add5");
	add10 = lookup_function("add10");
	printf("0x%x\n",add5(add5(5)));
	printf("0x%x\n",add10(5));
}
int main(){
	load_object();
	parse_object();
	execute_fucntion();
	return 1;
}
