# I am a comment, and I want to say that the variable CC will be
# the compiler to use.
CC=gcc
# Hey!, I am comment number 2. I want to say that CFLAGS will be the
# options I'll pass to the compiler.
CFLAGS= -c -Wall
all: crawl


crawl: crawl.o
	$(CC) crawl.o -o crawl

crawl.o: crawl.c
	$(CC) $(CFLAGS) crawl.c

clean:
	rm *o crawl
