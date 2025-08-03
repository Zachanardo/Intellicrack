
                .section .text
                .global _start
                _start:
                    mov r0, #42       @ exit status
                    mov r7, #1        @ sys_exit
                    swi #0            @ system call
            