#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PWSIZE 8

int func(void) {
  printf("What?");
}

// Test program for getLine().

int main(void) {

  size_t bufsize = (PWSIZE + 1) * sizeof(char);

  char *pw = (char *)malloc(bufsize);
  char *buf = (char *)malloc(bufsize);
  char *complete = (char *)malloc(bufsize);
  char newline[2];

  complete[0] = '\0';

  printf("Enter 8 Char Pwd> ");
  fflush(stdout);/**/
  fgets(pw, (int) bufsize, stdin);
  fgets(newline, sizeof(newline), stdin);
  if (newline[0] != '\n') exit(printf("passwordsize incorrect"));

  printf("Reenter this Pwd> ");
  fflush(stdout);
  fgets(buf, (int) bufsize, stdin);
  fgets(newline, sizeof(newline), stdin);
  if (newline[0] != '\n') exit(printf("passwordsize incorrect"));

  if (strlen(pw) != 8 || strncmp(buf, pw, bufsize) != 0) {
    fprintf(stderr, "Passwords needs to be at least 8 chars long and matching.\n");
    fflush(stderr);
    return 1;
  }

  strncat(complete, buf, PWSIZE);

  printf("String to append to pwd> ");
  fflush(stdout);

  fgets(buf, bufsize, stdin);

  size_t length = strlen(buf);

  if (length < 5) {
    printf("nothing to do");
    fflush(stdout);
    exit(0);
  }

  if (length > 5) {
    printf("5");
  }
  if (length > 8) {
    printf("10");
    bufsize *= length;
  }

  strncat(complete, buf, bufsize - strlen(complete));

  printf("We got [%s]\n", complete);
  fflush(stdout);

  free(pw);
  free(buf);
  free(complete);

  printf("Success :)");
  fflush(stdout);

  return 0;
}

