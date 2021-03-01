COMPILER         := cc
OPTIMIZATION_OPT := -O2
BASE_OPTIONS     := -pedantic-errors -Wall -Wextra -Werror -Wno-long-long -I./include
OPTIONS          := $(BASE_OPTIONS) $(OPTIMIZATION_OPT)
LINKER_OPT       := -L/usr/lib -lstdc++ -lm

all: lib examples

lib: include/dsa_verify.h
	$(COMPILER) -c $(OPTIONS) -o der.o        src/der.c        $(LIBRARY)
	$(COMPILER) -c $(OPTIONS) -o dsa_verify.o src/dsa_verify.c $(LIBRARY)
	$(COMPILER) -c $(OPTIONS) -o mp_math.o    src/mp_math.c    $(LIBRARY)
	$(COMPILER) -c $(OPTIONS) -o sha1.o       src/sha1.c       $(LIBRARY)

examples: lib include/dsa_verify.h
	$(COMPILER) $(OPTIONS) -o simple-verify examples/simple_verify.c *.o $(LIBRARY)
	$(COMPILER) $(OPTIONS) -o dsa-verify examples/verify_tool.c *.o $(LIBRARY)

clean:
	rm -f *.o
	rm -f simple-verify
	rm -f dsa-verify
