#include <stdio.h>

typedef unsigned char            u8;

/* how to combine the co-operands: subsets of cardinality 2, 3 or full set */
#define MODE_ODER_FULL  0
#define MODE_ODER_2     2
#define MODE_ODER_3     3

int main(int argc, char *argv[]) {
  generate_traces(MODE_ODER_FULL);
  return 0;
}
