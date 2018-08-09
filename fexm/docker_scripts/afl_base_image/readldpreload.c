/*
Vincent Ulitzsch
This file can be used to fuzz programs that expect user-input with afl-fuzz.
If input is read from stdin, a mock string is returned. Otherwise the original call is performed.
Basically we are doing function interposition here:
http://www.jayconrod.com/posts/23

*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <string.h>

size_t read(int fd, void *data, size_t size) {
  printf("Attempt to read from %d\n",isatty(fd));
  if(fd==0){ // If program attempts to read
    printf("Attempt to read from stdin\n");
    strcpy(data, "I love cats");
    return 12;
  } else {
    static size_t (*real_read)(int fd,void *data,size_t size) = NULL;
    if (!real_read)
        real_read = dlsym(RTLD_NEXT, "read");
    return real_read(fd,data,size);
  }
}