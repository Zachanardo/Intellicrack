
                .section .text
                .global _start
                _start:
                    mov x0, #42       // exit status
                    mov x8, #93       // sys_exit
                    svc #0            // system call
            