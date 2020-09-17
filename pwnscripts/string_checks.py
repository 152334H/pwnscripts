'''Misc. functions that pwntools may/maynot already have
'''
#TODO: This module requires cleanup. It currently serves a dual purpose as a generic "util" module, which is not desirable.
from re import findall, search
from pwnlib.log import getLogger
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import pack, unpack
from pwnscripts.context import context
log = getLogger('pwnlib.exploit')

def offset_to_regex(addr: int) -> str:
    return '.*' + hex(addr)[2:] + '$'

def offset_match(addr: int, offset: int) -> bool:
    return offset is None or bool(search(offset_to_regex(offset), hex(addr)))

# NOTE: ideally, n should default to context.bytes, but a default value is not dynamic...
def extract_first_bytes(s: bytes, n: int) -> int:
    return unpack(s[:n], n*8)

def extract_all_bytes(s: bytes, n: int) -> list:
    ''' Extract a list of unpacked bytes of length `n` from a bytestring
    Note that the list will truncate the bytestring to be divisible by `s`'''
    return map(lambda s: unpack(s,n*8), group(n, s, 'drop'))

def extract_all_hex(s: bytes) -> list:
    try: return list(map(lambda l: int(l,16), findall(b'0x[0-9a-f]+', s)))
    except IndexError: return []

def extract_first_hex(s: bytes) -> int:
    try: return int(findall(b'0x[0-9a-f]+', s)[0], 16)
    except IndexError: return -1

def is_wsl() -> bool: return b'Microsoft' in read('/proc/sys/kernel/osrelease') 
# TODO: compress all of theses is_X_address into a... class or something
def is_PIE_address(addr: int) -> bool:
    '''Heuristic for _potential_ PIE addresses
    
    Matches for '0x5[56][0-9a-f]{10}'
    '''
    if is_wsl():
        log.warn("The memory mappings for wsl1 are not always congruent"+\
                " with that of normal linux. Some things may break.")
    regex = ADDRESS_REGEX['pie'][context.arch]
    return addr > 0 and search(regex, hex(addr))

def is_stack_address(addr: int) -> bool:
    regex = ADDRESS_REGEX['stack'][context.arch]
    return addr > 0 and search(regex, hex(addr))

def is_libc_address(addr: int) -> bool:
    '''Heuristic for _potential_ libc addresses'''
    regex = ADDRESS_REGEX['libc'][context.arch]
    return addr > 0 and search(regex, hex(addr)) and not is_stack_address(addr)

def is_base_address(addr: int) -> bool:
    '''Heuristic for _potential_ base addresses'''
    regex = '.*000$'    # generic, TODO to check reasonable-ness
    return addr > 0 and search(regex, hex(addr))

def is_address(addr: int) -> bool:
    '''Any address heuristic.'''
    return any(f(addr) for f in [is_stack_address, is_libc_address, is_PIE_address])

def is_canary(addr: int) -> bool:
    '''Heuristic for _potential_ canary values'''
    return addr % 0x100 == 0 and pack(addr).count(b'\x00') < 3 and not is_address(addr)

ADDRESS_REGEX = {
    'pie': {'amd64': '0x5[56][0-9a-f]{10}', 'i386': '0x5[56][0-9a-f]{10}'},
    'stack': {'amd64': '0x7ff.*', 'i386': '0xff.*'},
    'libc': {'amd64':'0x7f.*', 'i386': '0xf7.*'},
    'canary': {'amd64': '.*00', 'i386': '.*00'}
}
