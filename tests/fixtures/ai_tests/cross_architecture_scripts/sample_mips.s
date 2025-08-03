
                .section .text
                .global _start
                _start:
                    li $v0, 4001      # sys_exit
                    li $a0, 42        # exit status
                    syscall           # system call
            