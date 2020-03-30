#include <stdio.h>

unsigned char pt[16] = {
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
  0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

unsigned char ct[16];

int main(void) {
  printf("plaintext:  ");
  for (int i = 0; i<16; i++) {
    printf("%02x", pt[i]);
  }
  printf("\n");

  AES_128_encrypt(ct, pt);

  printf("ciphertext: ");
  for (int i = 0; i<16; i++) {
    printf("%02x", ct[i]);
  }
  printf("\n");
}
