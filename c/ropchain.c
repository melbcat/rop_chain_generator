/* test1.c */

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	FILE *fp;
	fp = fopen("../a.out", "rb");
	unsigned long fileLen;
	char *buffer;

	//Get file length
	fseek(fp, 0, SEEK_END);
	fileLen=ftell(fp);
	fseek(fp, 0, SEEK_SET);
	printf("%ld\n",fileLen);

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
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");
	free(buffer);
	cs_close(&handle);

    return 0;
}
