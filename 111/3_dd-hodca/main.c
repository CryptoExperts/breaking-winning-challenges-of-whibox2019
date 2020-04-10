#include <stdio.h>

typedef unsigned char   u8;

#define MODE_ODER_FULL  0
#define MODE_ODER_2     2
#define MODE_ODER_3     3

int main(int argc, char *argv[]) {
  generate_traces(MODE_ODER_FULL);
  return 0;
}
