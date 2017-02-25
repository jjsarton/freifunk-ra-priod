LDFLAGS=-lnetfilter_queue -lnfnetlink -lmnl
CFLAGS=-Os -Wall -DDEBUG

all: ra-priod

ra-priod: ra-priod.c 
	$(CC) $(CFLAGS) $(LDFLAGS) -o ra-priod ra-priod.c

clean:
	rm ra-priod
