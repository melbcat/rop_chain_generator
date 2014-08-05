#include "rop.h"

char *binary;

csh handle;
cs_insn *insn;

char gadget_string[500];
unsigned int gadget_address;

unsigned long read_binary()
{
	FILE *fp;
	char file_name[20];
	unsigned long binary_len;
	printf("Enter binary file name: ");
	scanf("%s",file_name);
	fp = fopen(file_name, "rb");

	//Get file length
	fseek(fp, 0, SEEK_END);
	binary_len=ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//Allocate memory
	binary = (char *)malloc(binary_len+1);
	if(fp){
		fread(binary,binary_len,1,fp);
	}
	fclose(fp);
	return binary_len;
}

int rop_findgadgets(unsigned long binary_len)
{

	size_t count;

	strcpy(gadget_string,"");

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm_ex(handle, binary, binary_len, 0x08048000, 0, &insn);
	if (count > 0) {
		find_pop("ebp",count);
		//printf(" count = %d\n",count);
		cs_free(insn, count);
	} 
	else{
		printf("ERROR: Failed to disassemble given code!\n");
	}
	cs_close(&handle);
	return 0;
}

int find_pop(char* reg, size_t count)
{
	size_t j;
	for (j = 0; j < count; j++) {
		//printf("0x0%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
		if(!strcmp(insn[j].mnemonic,"ret") && !strcmp(insn[j-1].mnemonic,"pop") && !strcmp(insn[j-1].op_str,reg))
		{
			strcat(gadget_string,insn[j-1].mnemonic);
			strcat(gadget_string," ");
			strcat(gadget_string,insn[j-1].op_str);
			strcat(gadget_string," ; ");
			gadget_address = insn[j-1].address;
			strcat(gadget_string,"ret");
			printf("0x0%x: %s\n",gadget_address,gadget_string);
			strcpy(gadget_string,"");
			return 0;		
		}
	}
	printf("Can't find 'pop %s; ret'\n",reg);
	return -1;
}
