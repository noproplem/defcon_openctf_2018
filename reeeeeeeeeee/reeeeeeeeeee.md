# REeeeeeeeeee
Category: Binary, Reverse  
Creator : Soen  
Points  : 100

"Objdump -S; cat exploit | nc 172.31.2.54 0xeeee - https://scoreboard.openctf.com/reeeeeeeee-edf3ec2a9a2ce9fe3a6a23c25eac5b891adce8e4"

```
$ file reeeeeeeee-e837763d1052966e0657302f0f3877f1aecea926
reeeeeeeee-e837763d1052966e0657302f0f3877f1aecea926: ELF 64-bit MSB executable, SPARC V9, Sun UltraSPARC1 Extensions Required, relaxed memory ordering, version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=113d7a30ab521795c68612e230d79add1778adf5, not stripped
```

Sparc64. Yay. We try to connect to the service. On connection it sends an epoch timestamp, waits to receive some data, and then closes. Let's have a look at the disassembly:

```
$ cat disas
.text:0000000000100A80
.text:0000000000100A80 ! int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000100A80                 .global main
.text:0000000000100A80 main:                                   ! DATA XREF: _start+10↑o
.text:0000000000100A80                                         ! _start+1C↑o
.text:0000000000100A80
.text:0000000000100A80 arg_7BF         =  0x7BF
.text:0000000000100A80 arg_7C7         =  0x7C7
.text:0000000000100A80 time            =  0x7D3
.text:0000000000100A80 string          =  0x7D7
.text:0000000000100A80 arg_7F7         =  0x7F7
.text:0000000000100A80 arg_87F         =  0x87F
.text:0000000000100A80
.text:0000000000100A80                 save    %sp, -0xF0, %sp ! Save caller's window
.text:0000000000100A84                 mov     %i0, %g1        ! Move register
.text:0000000000100A88                 stx     %i1, [%fp+arg_7C7] ! Store extended
.text:0000000000100A8C                 stx     %i2, [%fp+arg_7BF] ! Store extended
.text:0000000000100A90                 st      %g1, [%fp+arg_87F] ! Store word
.text:0000000000100A94                 ldx     [%g7+0x28], %g1 ! Load extended
.text:0000000000100A98                 stx     %g1, [%fp+arg_7F7] ! Store extended
.text:0000000000100A9C                 mov     0, %g1          ! Move register
.text:0000000000100AA0                 mov     0x1E, %o0       ! Move register
.text:0000000000100AA4                 call    alarm           ! Call and link
.text:0000000000100AA8                 nop                     ! No operation
.text:0000000000100AAC                 mov     0, %o0          ! Move register
.text:0000000000100AB0                 call    time            ! Call and link
.text:0000000000100AB4                 nop                     ! No operation
.text:0000000000100AB8                 mov     %o0, %g1        ! Move register
.text:0000000000100ABC                 st      %g1, [%fp+time] ! Store word
.text:0000000000100AC0                 ld      [%fp+time], %g1 ! Load unsigned word
.text:0000000000100AC4                 srl     %g1, 0, %g1     ! Shift right logical
.text:0000000000100AC8                 mov     %g1, %o1        ! Move register
.text:0000000000100ACC                 set     unk_16DCC8, %o0 ! Load unsigned constant
.text:0000000000100AD4                 call    printf          ! Call and link
.text:0000000000100AD8                 nop                     ! No operation
.text:0000000000100ADC                 set     stdout, %g1     ! Load unsigned constant
.text:0000000000100AE4                 ldx     [%g1], %g1      ! Load extended
.text:0000000000100AE8                 mov     %g1, %o0        ! Move register
.text:0000000000100AEC                 call    fflush          ! Call and link
.text:0000000000100AF0                 nop                     ! No operation
.text:0000000000100AF4                 add     %fp, string, %g1 ! Add
.text:0000000000100AF8                 mov     0x20, %o2 ! ' ' ! Move register
.text:0000000000100AFC                 mov     %g1, %o1        ! Move register
.text:0000000000100B00                 mov     0, %o0          ! Move register
.text:0000000000100B04                 call    read            ! Call and link
.text:0000000000100B08                 nop                     ! No operation

.text:0000000000100B0C                 mov     %o0, %g1        ! Move register
.text:0000000000100B10                 cmp     %g1, 0x20 ! ' ' ! Compare
.text:0000000000100B14                 bne     %xcc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B18                 nop                     ! No operation

.text:0000000000100B1C                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100B20                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B24                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B28                 cmp     %g1, 0x41 ! 'A' ! Compare
.text:0000000000100B2C                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B30                 nop                     ! No operation

.text:0000000000100B34                 ldub    [%fp+string+1], %g2 ! Load unsigned byte
.text:0000000000100B38                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100B3C                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100B40                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B44                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B48                 cmp     %g1, 2          ! Compare
.text:0000000000100B4C                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B50                 nop                     ! No operation

.text:0000000000100B54                 add     %fp, string, %g1 ! Add
.text:0000000000100B58                 inc     2, %g1          ! Increment
.text:0000000000100B5C                 ld      [%g1], %g2      ! Load unsigned word
.text:0000000000100B60                 ld      [%fp+time], %g1 ! Load unsigned word
.text:0000000000100B64                 cmp     %g2, %g1        ! Compare
.text:0000000000100B68                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B6C                 nop                     ! No operation

.text:0000000000100B70                 ldub    [%fp+string+6], %g1 ! Load unsigned byte
.text:0000000000100B74                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B78                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B7C                 cmp     %g1, 0x41 ! 'A' ! Compare
.text:0000000000100B80                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B84                 nop                     ! No operation

.text:0000000000100B88                 ldub    [%fp+string+7], %g1 ! Load unsigned byte
.text:0000000000100B8C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B90                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B94                 cmp     %g1, 0x53 ! 'S' ! Compare
.text:0000000000100B98                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B9C                 nop                     ! No operation

.text:0000000000100BA0                 ldub    [%fp+string+8], %g2 ! Load unsigned byte
.text:0000000000100BA4                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100BA8                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100BAC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100BB0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100BB4                 cmp     %g1, 0xD        ! Compare
.text:0000000000100BB8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100BBC                 nop                     ! No operation

.text:0000000000100BC0                 ldub    [%fp+string+9], %g2 ! Load unsigned byte
.text:0000000000100BC4                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100BC8                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100BCC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100BD0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100BD4                 cmp     %g1, 0xA        ! Compare
.text:0000000000100BD8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100BDC                 nop                     ! No operation

.text:0000000000100BE0                 ldub    [%fp+string+0xA], %g2 ! Load unsigned byte
.text:0000000000100BE4                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100BE8                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100BEC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100BF0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100BF4                 cmp     %g1, 5          ! Compare
.text:0000000000100BF8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100BFC                 nop                     ! No operation

.text:0000000000100C00                 ldub    [%fp+string+0xB], %g2 ! Load unsigned byte
.text:0000000000100C04                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100C08                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100C0C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100C10                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100C14                 cmp     %g1, 9          ! Compare
.text:0000000000100C18                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100C1C                 nop                     ! No operation

.text:0000000000100C20                 ldub    [%fp+string+0xC], %g2 ! Load unsigned byte
.text:0000000000100C24                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100C28                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100C2C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100C30                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100C34                 cmp     %g1, 0x71 ! 'q' ! Compare
.text:0000000000100C38                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100C3C                 nop                     ! No operation

.text:0000000000100C40                 ldub    [%fp+string+0xD], %g2 ! Load unsigned byte
.text:0000000000100C44                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100C48                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100C4C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100C50                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100C54                 cmp     %g1, 0x70 ! 'p' ! Compare
.text:0000000000100C58                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100C5C                 nop                     ! No operation

.text:0000000000100C60                 ldub    [%fp+string+0xE], %g2 ! Load unsigned byte
.text:0000000000100C64                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100C68                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100C6C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100C70                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100C74                 cmp     %g1, 0x2A ! '*' ! Compare
.text:0000000000100C78                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100C7C                 nop                     ! No operation

.text:0000000000100C80                 ldub    [%fp+string+0xF], %g2 ! Load unsigned byte
.text:0000000000100C84                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100C88                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100C8C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100C90                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100C94                 cmp     %g1, 0x12       ! Compare
.text:0000000000100C98                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100C9C                 nop                     ! No operation

.text:0000000000100CA0                 ldub    [%fp+string+0x10], %g1 ! Load unsigned byte
.text:0000000000100CA4                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100CA8                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100CAC                 cmp     %g1, 0x44 ! 'D' ! Compare
.text:0000000000100CB0                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100CB4                 nop                     ! No operation

.text:0000000000100CB8                 ldub    [%fp+string+0x11], %g1 ! Load unsigned byte
.text:0000000000100CBC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100CC0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100CC4                 cmp     %g1, 0x4A ! 'J' ! Compare
.text:0000000000100CC8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100CCC                 nop                     ! No operation

.text:0000000000100CD0                 ldub    [%fp+string+0x12], %g1 ! Load unsigned byte
.text:0000000000100CD4                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100CD8                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100CDC                 cmp     %g1, 0x30 ! '0' ! Compare
.text:0000000000100CE0                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100CE4                 nop                     ! No operation

.text:0000000000100CE8                 ldub    [%fp+string+0x13], %g1 ! Load unsigned byte
.text:0000000000100CEC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100CF0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100CF4                 cmp     %g1, 0x61 ! 'a' ! Compare
.text:0000000000100CF8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100CFC                 nop                     ! No operation

.text:0000000000100D00                 ldub    [%fp+string+0x14], %g1 ! Load unsigned byte
.text:0000000000100D04                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D08                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D0C                 cmp     %g1, 0x73 ! 's' ! Compare
.text:0000000000100D10                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D14                 nop                     ! No operation

.text:0000000000100D18                 ldub    [%fp+string+0x15], %g1 ! Load unsigned byte
.text:0000000000100D1C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D20                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D24                 cmp     %g1, 0x64 ! 'd' ! Compare
.text:0000000000100D28                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D2C                 nop                     ! No operation

.text:0000000000100D30                 ldub    [%fp+string+0x16], %g1 ! Load unsigned byte
.text:0000000000100D34                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D38                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D3C                 cmp     %g1, 0x6B ! 'k' ! Compare
.text:0000000000100D40                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D44                 nop                     ! No operation

.text:0000000000100D48                 ldub    [%fp+string+0x17], %g1 ! Load unsigned byte
.text:0000000000100D4C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D50                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D54                 cmp     %g1, 0x6A ! 'j' ! Compare
.text:0000000000100D58                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D5C                 nop                     ! No operation

.text:0000000000100D60                 ldub    [%fp+string+0x18], %g1 ! Load unsigned byte
.text:0000000000100D64                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D68                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D6C                 cmp     %g1, 0x46 ! 'F' ! Compare
.text:0000000000100D70                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D74                 nop                     ! No operation

.text:0000000000100D78                 ldub    [%fp+string+0x19], %g1 ! Load unsigned byte
.text:0000000000100D7C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D80                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D84                 cmp     %g1, 0x46 ! 'F' ! Compare
.text:0000000000100D88                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100D8C                 nop                     ! No operation

.text:0000000000100D90                 ldub    [%fp+string+0x1A], %g1 ! Load unsigned byte
.text:0000000000100D94                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100D98                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100D9C                 cmp     %g1, 0x32 ! '2' ! Compare
.text:0000000000100DA0                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100DA4                 nop                     ! No operation

.text:0000000000100DA8                 ldub    [%fp+string+0x1B], %g1 ! Load unsigned byte
.text:0000000000100DAC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100DB0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100DB4                 cmp     %g1, 0x39 ! '9' ! Compare
.text:0000000000100DB8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100DBC                 nop                     ! No operation

.text:0000000000100DC0                 ldub    [%fp+string+0x1C], %g1 ! Load unsigned byte
.text:0000000000100DC4                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100DC8                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100DCC                 cmp     %g1, 0x73 ! 's' ! Compare
.text:0000000000100DD0                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100DD4                 nop                     ! No operation

.text:0000000000100DD8                 ldub    [%fp+string+0x1D], %g1 ! Load unsigned byte
.text:0000000000100DDC                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100DE0                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100DE4                 cmp     %g1, 0x6C ! 'l' ! Compare
.text:0000000000100DE8                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100DEC                 nop                     ! No operation

.text:0000000000100DF0                 ldub    [%fp+string+0x1E], %g1 ! Load unsigned byte
.text:0000000000100DF4                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100DF8                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100DFC                 cmp     %g1, 0x61 ! 'a' ! Compare
.text:0000000000100E00                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100E04                 nop                     ! No operation

.text:0000000000100E08                 ldub    [%fp+string+0x1F], %g1 ! Load unsigned byte
.text:0000000000100E0C                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100E10                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100E14                 cmp     %g1, 0x73 ! 's' ! Compare
.text:0000000000100E18                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100E1C                 nop                     ! No operation

.text:0000000000100E20                 set     aYouWin, %o0    ! "You win!"
.text:0000000000100E28                 call    puts            ! Call and link
.text:0000000000100E2C                 nop                     ! No operation
.text:0000000000100E30                 set     aBinSh, %o0     ! "/bin/sh"
.text:0000000000100E38                 call    system          ! Call and link
.text:0000000000100E3C                 nop                     ! No operation

.text:0000000000100E40
.text:0000000000100E40 failed:                                 ! CODE XREF: main+94↑j
.text:0000000000100E40                                         ! main+AC↑j ...
.text:0000000000100E40                 mov     0, %g1          ! Move register
.text:0000000000100E44                 sra     %g1, 0, %g1     ! Shift right arithmetic
.text:0000000000100E48                 mov     %g1, %i0        ! Move register
.text:0000000000100E4C                 ldx     [%fp+arg_7F7], %g1 ! Load extended
.text:0000000000100E50                 ldx     [%g7+0x28], %g2 ! Load extended
.text:0000000000100E54                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100E58                 mov     0, %g2          ! Move register
.text:0000000000100E5C                 brz     %g1, loc_100E6C ! Branch on contents of integer register with prediction
.text:0000000000100E60                 nop                     ! No operation
.text:0000000000100E64                 call    __stack_chk_fail ! Call and link
.text:0000000000100E68                 nop                     ! No operation
.text:0000000000100E6C
.text:0000000000100E6C loc_100E6C:                             ! CODE XREF: main+3DC↑j
.text:0000000000100E6C                 return  %i7+8           ! Return
.text:0000000000100E70                 nop                     ! No operation
.text:0000000000100E70 ! End of function main
```

The win location is on 0000000000100E20, and is the basic fall-through once we pass a bunch of checks. If we reach that we get a shell. Cool. Let's back-track.

The binary sets an alarm to eventually kill all connections, then gets and prints the timestamp and reads some data. There's the first failure condition. The data must be 0x20 bytes long.

What follows is a bunch of checks on each byte of the input, starting and index 0 and moving on byte by byte:

```
.text:0000000000100B1C                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100B20                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B24                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B28                 cmp     %g1, 0x41 ! 'A' ! Compare
.text:0000000000100B2C                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B30                 nop                     ! No operation

.text:0000000000100B34                 ldub    [%fp+string+1], %g2 ! Load unsigned byte
.text:0000000000100B38                 ldub    [%fp+string], %g1 ! Load unsigned byte
.text:0000000000100B3C                 btog    %g2, %g1        ! Bit toggle
.text:0000000000100B40                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B44                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B48                 cmp     %g1, 2          ! Compare
.text:0000000000100B4C                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B50                 nop                     ! No operation

.text:0000000000100B54                 add     %fp, string, %g1 ! Add
.text:0000000000100B58                 inc     2, %g1          ! Increment
.text:0000000000100B5C                 ld      [%g1], %g2      ! Load unsigned word
.text:0000000000100B60                 ld      [%fp+time], %g1 ! Load unsigned word
.text:0000000000100B64                 cmp     %g2, %g1        ! Compare
.text:0000000000100B68                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B6C                 nop                     ! No operation

.text:0000000000100B70                 ldub    [%fp+string+6], %g1 ! Load unsigned byte
.text:0000000000100B74                 sll     %g1, 24, %g1    ! Shift left logical
.text:0000000000100B78                 sra     %g1, 24, %g1    ! Shift right arithmetic
.text:0000000000100B7C                 cmp     %g1, 0x41 ! 'A' ! Compare
.text:0000000000100B80                 bne     %icc, failed    ! Branch on integer condition codes with prediction
.text:0000000000100B84                 nop                     ! No operation

[...]
```

The rest of the checks look similar to those of index 0 and 1.

For byte 0 (and most others) it loads in our first byte into a 4-byte register. It then bit shifts the register back and forth to clear it, isolating the byte in question (assuming the high bit isn't set). Then checks that the register contains 'A' or fails. We've got the first char.

Byte 1, when xor'ed with byte 0, should give 2. So we get `chr(ord('A')^2)=='C'`. It next compares bytes 2 through 5 to the timestamp that was saved and printed earlier. So we'll have to parse that.

Bytes 6 onwards are just like byte 0 or 1. Simple checks. This is what we ended up with:

```
$ cat doit.py
#!/usr/bin/env python
import struct
from pwn import *

s = remote('172.31.2.54', 0xeeee)
data = s.recvline().strip()

buf = 'AC'
buf += struct.pack('>I', int(data))
buf += 'ASLKDH01kS'
buf += 'DJ0asdkjFF29slas'

assert len(buf) == 0x20
s.send(buf)
s.interactive()
```

```
$ python doit.py
reeeeeeeeeee$ # Gotcha. Looking around a bit... Seeing nothing.
reeeeeeeeeee$ find ~/
find: '~/': Permission denied
```

Huh.

If I had put a flag somewhere, what would I have called it?

```
$ python doit.py
reeeeeeeeeee$ cat ~/flag
flag{ReEeeEee3eEee3eE3e3eeee}
# Not really, but that flag's gone now and you get the point.
```

REeeeeeeeeee!
