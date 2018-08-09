
#include<stdio.h>
#include <unistd.h>
/* Our structure */
struct rec
{
    int x,y,z;
};

int main(int argc,char* argv[])
{
    // A mock binary that simulates a timeout, i.e. the binary takes a lot of time till it finished.
    sleep(3000);
    if(argc<=1){
      printf("Usage: %s jpg_file\n",argv[0]);
    }
    unsigned char ch;
    unsigned char magic_bytes[4];
        int counter;
        FILE *ptr_myfile;
        struct rec my_record;

        ptr_myfile=fopen(argv[1],"rb");
        if (!ptr_myfile)
        {
            printf("Unable to open file!");
            return 1;
        }
    int i =0;
    // obtain file size:
    fseek (ptr_myfile , 0 , SEEK_END);
    int lSize = ftell (ptr_myfile);
    rewind (ptr_myfile);
    fread(magic_bytes,1,4,ptr_myfile);
    if(!(magic_bytes[0]==0xFF&&magic_bytes[1]==0xD8&&magic_bytes[2]==0xFF&&magic_bytes[3]==0xE0)){
      printf("No JPG file");
            return 0;
    }
    sleep(30);
    printf("Magic Bytes\n");
    for(i=0;i<4;++i){
      printf("%02X ",magic_bytes[i]);
    }
    printf("\n$$$\n");
    i=0;
        rewind(ptr_myfile);
    for(int i=0;i<lSize;++i)
    {
      ch = fgetc(ptr_myfile);
      printf("%02X ",ch);
      if( !(i % 16) ){
        putc('\n', stdout);
      }
    }
    printf("\n");
    fclose(ptr_myfile);
    return 0;
}
