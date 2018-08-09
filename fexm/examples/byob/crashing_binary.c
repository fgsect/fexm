#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char * argv[]){
    char *buff;

    if ((buff = malloc(10)) == NULL)
      abort();

    if ((fd = fopen(argv[1], "r")) == NULL)
      abort();
    fread(buff, 10, 1, fd);

    if (strncmp(buff, "h", 1) == 0)
    {
      if (strncmp(buff, "he", 2) == 0)
      {
        if (strncmp(buff, "hel", 3) == 0)
        {
          if (strncmp(buff, "hell", 4) == 0)
          {
            if (strncmp(buff, "hello", 5) == 0)
            {
              buff[9] = 0; //just to be sure...
              fprintf(stderr, "Nailed it ! input file is %s\n", buff);
              abort();
            }
          }
          else
          {
            abort(); // it should be found quick
          }
        }
      }
    }
    free(buff);
    fclose(fd);
    return 0;
}