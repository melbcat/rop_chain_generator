#ifndef _rop_h
#define _rop_h
#define _rop_h

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

extern char *binary;

unsigned long read_binary();
int rop_findgadgets(unsigned long binary_len);
int find_pop(char* reg, size_t count);

#endif
