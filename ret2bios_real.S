[org 0x7c00]
[bits 32]

; Exit compatibility and protected modes to start the kernel.


compat:
      ; disable paging
      mov          eax, cr0
      and          eax, 0x7fffffff
      mov          cr0, eax

      ; disable long mode
      mov          ecx, 0x0c0000080
      rdmsr
      btc          eax, 8
      wrmsr

prot32:
      ; disable 32-bit mode
      lgdt         [fs:gdt_desc]
      lidt         [fs:ivt]
      jmp          code16:prot16

[bits 16]
prot16:
      ; disable protected mode
      mov          eax, cr0
      and          al, 0xfe
      mov          cr0, eax
      xor          eax, eax
      jmp          0x0:real

real:
      ; start the kernel in real mode at 0x20200
      mov          ax, 0x2000
      mov          ds, ax
      mov          es, ax
      mov          fs, ax
      mov          gs, ax
      mov          ss, ax
      mov          sp, 0xe000
      jmp          0x2020:0x0

gdt_desc:
      dw gdt_end - gdt - 1
      dd gdt

align 4
gdt:
      dq 0
code16: equ $ - gdt
      dw 0xffff    ; limit_low
      dw 0         ; base_low
      db 0         ; base_mid
      db 10011010b ; access byte
      db 10001111b ; granularity
      db 0         ; base_high
gdt_end:

align 4
ivt:
      dw           0x3ff
      dq           0
