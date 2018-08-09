
#include<stdio.h>
#include <unistd.h>

/* Our structure */
struct rec
{
    int x,y,z;
};

int main(int argc,char* argv[])
{
    /*
    This is a mock binary that simulates a binary that processes jpg files. In particular
    it processes files that have the four magic bytes 0xFF0xD80xFF0xE0.
    */
    unsigned char ch;
    unsigned char magic_bytes[4];
    int counter;
    FILE *ptr_myfile;
    struct rec my_record;
    int dupped_stdin = dup(0);
    FILE *dupped_stdin_stream = fdopen(dupped_stdin,"r");
    fread(magic_bytes,1,4,dupped_stdin_stream);
    if(!(magic_bytes[0]==0xFF&&magic_bytes[1]==0xD8&&magic_bytes[2]==0xFF&&magic_bytes[3]==0xE0)){
    printf("No JPG file");
        return 0;
    }
    printf("Magic Bytes\n");
    for(int i=0;i<4;++i){
    printf("%02X ",magic_bytes[i]);
    }
    printf("\n$$$\n");
    for(int i=0;i<20;++i)
    {
    ch = fgetc(stdin);
    printf("%02X ",ch);
    if( !(i % 16) ){
            putc('\n', stdout);
        }
    }
    printf("\n");
    return 0;
}
