ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsclamav.so

#
# Objects to build.
#
OBJS     = nsclamav.o

MODLIBS	 = -L/usr/local/lib -lclamav

include  $(NAVISERVER)/include/Makefile.module
