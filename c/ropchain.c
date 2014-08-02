/* test1.c */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	FILE *fp;
	char file_name[20];
	printf("Enter binary file name: ");
	scanf("%s",file_name);
	fp = fopen(file_name, "rb");
	unsigned long fileLen;
	char *buffer;

	int gadget_len = 0;
	char gadget_string[500];
	unsigned int gadget_address;
	strcpy(gadget_string,"");

	//Get file length
	fseek(fp, 0, SEEK_END);
	fileLen=ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//Allocate memory
	buffer = (char *)malloc(fileLen+1);
	if(fp){
		fread(buffer,fileLen,1,fp);
	}
	fclose(fp);
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm_ex(handle, buffer, fileLen, 0x08048000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			//printf("0x0%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
			
			if(gadget_len == 0){
				gadget_address = insn[j].address;
			}
			if(!strcmp(insn[j].mnemonic,"ret")){
					
				strcat(gadget_string,"ret");
				printf("0x0%x: %s\n",gadget_address,gadget_string);		
				gadget_address = gadget_address + insn[j].size;
				strcpy(gadget_string,"");
				gadget_len = 0;
			}
			else{
				gadget_len = gadget_len + 1;
				strcat(gadget_string,insn[j].mnemonic);
				strcat(gadget_string," ");
				strcat(gadget_string,insn[j].op_str);
				strcat(gadget_string," ; ");
			}
			if(gadget_len>10){
				gadget_len = 0;
				strcpy(gadget_string,"");
			}
			
		}
		cs_free(insn, count);
	} 
	else{
		printf("ERROR: Failed to disassemble given code!\n");
	}
	free(buffer);
	cs_close(&handle);
	return 0;
}
