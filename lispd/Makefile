#
#	Makefile for lispd
#

LIBS		+= -lconfuse -lssl -lcrypto
INC		+= lispd.h
OBJS		= cmdline.o timerfd.o lispd.o lispd_config.o lispd_syslog.o	\
		  lispd_lib.o lispd_ipc.o lispd_map_register.o		\
		  patricia/patricia.o lispd_map_request.o cksum.o	\
		  lispd_patricia.o lispd_map_reply.o lispd_iface_mgmt.o	\
		  lispd_iface_list.o
EXE		= lispd
#CC		= gcc
#CFLAGS		= -g -DDEBUG=3
#MAKEFILE	= Makefile
#PREFIX		= /usr/local/sbin

$(EXE): $(OBJS) 
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $^
#	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

%.o: %.c $(INC)
	$(CC) $(CFLAGS) -c -o $@ $<
#%.o: %.c $(DEPS) $(INC) $(MAKEFILE)
#	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f *.o cmdline.[ch] $(EXE) patricia/*.o cscope.out
#
#install: $(EXE)
#	mkdir -p $(PREFIX) && cp $(EXE) $(PREFIX)
#
#tags:
#	cscope -R -b
