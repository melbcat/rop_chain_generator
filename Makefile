# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone

ropchain: ropchain.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@

%.o: %.c
	${CC} -c $< -o $@