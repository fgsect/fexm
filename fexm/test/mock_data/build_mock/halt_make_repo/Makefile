# I am a comment, and I want to say that the variable CC will be
# the compiler to use.
CC=gcc
# Hey!, I am comment number 2. I want to say that CFLAGS will be the
# options I'll pass to the compiler.
CFLAGS= -c -Wall

all: main

main: main.o
	$(CC) main.o -o main

main.o: main.c
	$(CC) $(CFLAGS) main.c
	# Wait for the input
	@read -p "Waiting for input:" module;


clean:
	rm *o main
