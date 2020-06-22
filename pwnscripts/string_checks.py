'''Miscellanous functions that pwntools may/maynot already have'''
from pwn import *
from re import findall, search
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
