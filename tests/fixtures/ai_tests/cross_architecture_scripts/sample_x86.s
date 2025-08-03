
                .section .text
                .global _start
                _start:
                    mov $1, %eax      # sys_exit
                    mov $42, %ebx     # exit status
                    int $0x80         # system call
            