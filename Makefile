COMPILER         := cc
ARCHIVER         := ar
OPTIMIZATION_OPT := -O2
BASE_OPTIONS     := -pedantic-errors -Wall -Wextra -Werror -Wno-long-long -I./include
OPTIONS          := $(BASE_OPTIONS) $(OPTIMIZATION_OPT)

all: dsa-verify.a examples

examples: simple-verify dsa-verify

dsa-verify.a: include/dsa-verify.h src/*.c src/*.h
	$(COMPILER) -c $(OPTIONS) src/der.c
	$(COMPILER) -c $(OPTIONS) src/dsa-verify.c
	$(COMPILER) -c $(OPTIONS) src/mp_math.c
	$(ARCHIVER) rcs dsa-verify.a der.o dsa-verify.o mp_math.o

simple-verify: include/dsa-verify.h dsa-verify.a
	$(COMPILER) $(OPTIONS) -o simple-verify examples/simple-verify.c dsa-verify.a

dsa-verify: include/dsa-verify.h dsa-verify.a
	$(COMPILER) $(OPTIONS) -o dsa-verify examples/verify-tool.c dsa-verify.a

clean:
	rm -f *.o
	rm -f dsa-verify.a
	rm -f simple-verify
	rm -f dsa-verify
