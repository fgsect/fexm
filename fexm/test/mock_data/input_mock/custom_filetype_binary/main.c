
#include<stdio.h>

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
    if(argc<=1){
    printf("Usage: %s file\n",argv[0]);
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
    if(!(magic_bytes[0]==0x99&&magic_bytes[1]==0x99&&magic_bytes[2]==0x99&&magic_bytes[3]==0x99)){ // None type
    printf("No JPG file");
        return 0;
    }
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
