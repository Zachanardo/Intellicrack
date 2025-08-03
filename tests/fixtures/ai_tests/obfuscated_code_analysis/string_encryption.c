
        #include <stdio.h>
        
        char encrypted[] = {0x48^0x42, 0x65^0x42, 0x6c^0x42, 0x6c^0x42, 0x6f^0x42, 0x00^0x42};
        
        int main() {
            for(int i = 0; i < 6; i++) {
                encrypted[i] ^= 0x42;
            }
            printf("%s World\n", encrypted);
            return 0;
        }
        