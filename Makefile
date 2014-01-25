##-*- makefile -*-############################################################
#
#  System        : 
#  Module        : 
#  Object Name   : $RCSfile$
#  Revision      : $Revision$
#  Date          : $Date$
#  Author        : $Author$
#  Created By    : Russ Magee
#  Created       : Fri Jan 10 16:33:53 2014
#  Last Modified : <140110.1701>
#
#  Description	
#
#  Notes
#
#  History
#	
#  $Log$
#
##############################################################################
#
#  Copyright (c) 2014 Russ Magee.
# 
#  All Rights Reserved.
# 
#  This  document  may  not, in  whole  or in  part, be  copied,  photocopied,
#  reproduced,  translated,  or  reduced to any  electronic  medium or machine
#  readable form without prior written consent from Russ Magee.
#
##############################################################################

MTWIST = mtwist-1.5

CC = gcc
COPTS = -std=c99 -I$(MTWIST) $(BUILDFLAGS) -c

LC = gcc
LOPTS = -std=c99

OBJS = mtc.o
LIBS = $(MTWIST)/mtwist.o

all: mtc

%.o:%.c
	$(CC) $(COPTS) -o $@ $<

mtc: $(OBJS) $(LIBS)
	$(LC) $(LOPTS) -o $@ $(OBJS) $(LIBS)

.PHONY: clean

clean:
	$(RM) $(OBJS)

