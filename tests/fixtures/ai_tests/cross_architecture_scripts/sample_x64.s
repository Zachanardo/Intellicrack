
                .section .text
                .global _start
                _start:
                    mov $60, %rax     # sys_exit
                    mov $42, %rdi     # exit status
                    syscall           # system call
            