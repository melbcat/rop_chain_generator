#include "rop.h"

int main(void)
{
	unsigned long binary_len;
	binary_len = read_binary();
	rop_findgadgets(binary_len);
	free(binary);
	return 0;
}

