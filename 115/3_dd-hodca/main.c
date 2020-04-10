#include <stdio.h>

typedef unsigned char            u8;

/* how to combine the co-operands: subsets of cardinality 2, 3 or full set */
#define MODE_ODER_FULL  0
#define MODE_ODER_2     2
#define MODE_ODER_3     3

int main(int argc, char *argv[]) {
  // argv[1] should be the attacked byte

  int byte = strtol(argv[1], NULL, 10);
  generate_traces(MODE_ODER_FULL, byte);

  return 0;
}
