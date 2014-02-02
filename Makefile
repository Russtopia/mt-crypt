MTWIST = mtwist-1.5
SHALIB = sha2-1.0.1
KISSLIB = kiss-2011

IDIRS = -I$(MTWIST) -I$(SHALIB) -I$(KISSLIB)

CC = gcc
COPTS = -std=c99 $(IDIRS) $(BUILDFLAGS) -c

LC = gcc
LOPTS = -std=c99

OBJS = mtc.o
LIBS = $(MTWIST)/mtwist.o $(SHALIB)/sha2.o $(KISSLIB)/kiss-2011.o

all: mtc

%.o:%.c
	$(CC) $(COPTS) -o $@ $<

mtc: $(OBJS) $(LIBS)
	$(LC) $(LOPTS) -o $@ $(OBJS) $(LIBS)

.PHONY: clean

clean:
	$(RM) $(OBJS)
	make -C $(KISSLIB) clean

