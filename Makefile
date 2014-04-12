C=gcc
CFLAGS=-W -pedantic
LDFLAGS=-lpcap

all: wakeonarp

wakeonarp: wakeonarp.o 
	$(CC) -o wakeonarp wakeonarp.o $(LDFLAGS)

wakeonarp.o: wakeonarp.c
	$(CC) -o wakeonarp.o -c wakeonarp.c $(CFLAGS)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf wakeonarp

