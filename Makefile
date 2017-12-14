CFLAGS = -lpthread 
LIBS=

all:
	gcc -o arpdiscover arpdiscover.c $(CFLAGS) $(LIBS)
	gcc -o arpspoofing arpspoofing.c $(CFLAGS) $(LIBS)

clean:
	rm -f arpdiscover arpspoofing
