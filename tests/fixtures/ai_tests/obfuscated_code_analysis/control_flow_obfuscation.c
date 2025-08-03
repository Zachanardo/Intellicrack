
        #include <stdio.h>
        
        int main() {
            int x = 42;
            // Control flow obfuscation
            if ((x ^ 0xAA) == (42 ^ 0xAA)) {
                goto label1;
            }
            return 1;
            
        label1:
            x = x * 2;
            if (x == 84) {
                printf("Obfuscated Hello World\n");
            }
            return 0;
        }
        