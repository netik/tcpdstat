PREFIX=/usr/local
PROGS=tcpdstat
OBJS=stat.o net_read.o ip_flow.o
PWD=tcpdstat-uw

SYS_DEFINES=	-DLINUX -D__FAVOR_BSD -D_LARGEFILE_SOURCE=1 \
		-D_FILE_OFFSET_BITS=64 -L../libpcap-0.7.1
SYS_INCLUDES=	-I../libpcap-0.7.1

FLAGS=		-g -Wall
DEFINES=	$(SYS_DEFINES)
INCLUDES=	-I. $(SYS_INCLUDES)
INSTALL=install

all: $(PROGS)

install: $(PROGS)
	# $(INSTALL) $(COPY) -m 0755 $(PROGS) $(PREFIX)/bin
	cp tcpdstat $(PREFIX)/bin
	chmod 0755 $(PREFIX)/bin/tcpdstat 

tar:
	(cd ..; tar -cvf tcpdstat-uw.tar $(PWD); \
	md5sum tcpdstat-uw.tar > tcpdstat-uw.tar.md5sum)

tcpdstat: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(OBJS) -lpcap -lm $(SYS_LIBS)

.c.o: 
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:;		-rm -f $(PROGS) *.o core *.core *.bak ,* *~ "#"*
