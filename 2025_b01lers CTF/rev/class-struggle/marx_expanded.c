#include <stdio.h>
#include <string.h>

unsigned char tfkysf(unsigned char j, int vfluhzftxror)
{
     vfluhzftxror &= 7;
     return (j << vfluhzftxror) | (j >> (8 - vfluhzftxror));
}
unsigned char b(unsigned char j, int vfluhzftxror)
{
     vfluhzftxror &= 7;
     return (j >> vfluhzftxror) | (j << (8 - vfluhzftxror));
}
unsigned char jistcuazjdma(unsigned char jistcuazjdma, int mpnvtqeqmsgc)
{
     jistcuazjdma ^= (mpnvtqeqmsgc * 
                      37);
     jistcuazjdma = tfkysf(jistcuazjdma, (mpnvtqeqmsgc + 3) % 7);
     jistcuazjdma += 42;
     return jistcuazjdma;
}
int flag_checker(const char *user_input)
{
     const unsigned char predefine_set[] = {0x32, 0xc0, 0xbf, 0x6c, 0x61, 0x85, 0x5c, 0xe4, 0x40, 0xd0, 0x8f, 0xa2, 0xef, 0x7c, 0x4a, 0x2, 0x4, 0x9f, 0x37, 0x18, 0x68, 0x97, 0x39, 0x33, 0xbe, 0xf1, 0x20, 0xf1, 0x40, 0x83, 0x6, 0x7e, 0xf1, 0x46, 0xa6, 0x47, 0xfe, 0xc3, 0xc8, 0x67, 0x4, 0x4d, 0xba, 0x10, 0x9b, 0x33};
     int user_inptu_len = strlen(user_input);
     if (user_inptu_len != sizeof(predefine_set))
     {
          return 0;
     }
     for (int mpnvtqeqmsgc = 0; mpnvtqeqmsgc < user_inptu_len; mpnvtqeqmsgc++)
     {
          unsigned char z = jistcuazjdma(user_input[mpnvtqeqmsgc], mpnvtqeqmsgc);
          unsigned char e = b((z & 0xF0) | ((~z) & 0x0F),
                              mpnvtqeqmsgc % 8);
          if (e != predefine_set[mpnvtqeqmsgc])
          {
               return 0;
          }
     }
     return 1;
}


int main(void)
{

     char user_input[64];
     printf("Please input the flag: ");
     fgets(user_input, sizeof(user_input), stdin);
     char *nl = strchr(user_input, '\n');
     if (nl)
     {
          *nl = 0;
     }
     if (flag_checker(user_input))
     {
          puts("Correct!");
     }
     else
     {
          puts("No.");
     }
     return 0;
}
