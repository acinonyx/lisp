#	Makefile for lispconf
LIBS		+= -lm
INC		+= ./lisp_ipc.h
OBJS		= cmdline.o lispconf.o
EXE		= lispconf

$(EXE): $(OBJS) 
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $^

%.o: %.c $(INC)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(EXE)

