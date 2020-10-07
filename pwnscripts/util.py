'''Misc. functions that pwntools may/maynot already have
'''
from re import findall, search
from collections import defaultdict
from pwnlib.log import getLogger
from pwnlib.util.misc import read
from pwnlib.util.lists import group
from pwnlib.util.packing import pack, unpack, unpack_many
from pwnscripts.context import context
log = getLogger('pwnlib.exploit')

#TODO: This module _really_ requires cleanup. It currently serves a dual purpose as a generic "util" module, which is not desirable.
'''Planned refactoring of this...
0. Scan pwntools again to make sure that this doesn't exist
1. give is_wsl() a different naming. It shouldn't sound related to is_X_address
2. Make a `util` folder (maybe named diff from pwntools?). Have it contain `extract.py` and `is.py`
   * note: naming of `is.py` not-there-yet since `is` is a keyword
3. Shotgun patch all of the renamed methods throughout pwnscripts
4. Maybe make a more potent method for is_X_address (not sure yet)
'''
# NOTE: ideally, n should default to context.bytes, but a default value is not dynamic...
def unpack_bytes(s: bytes, n: int=None) -> int:
    '''Unpack the first `n` bytes of a bytestring,
    defaulting to n=context.bytes'''
    if n is None: n = context.bytes
    return unpack(s[:n], n*8)
def unpack_many_bytes(s: bytes, n: int=None) -> int:
    '''Unpack `s` into groups of `n` bytes, unpacked.
    n=context.bytes by default'''
    if n is None: n = context.bytes
    return unpack_many(s, n*8)
def unpack_hex(s: bytes) -> int:
    '''Extract the first hex number found in a bytestring
    >>> unpack_hex(b'AOJFW219j0x12392jafbcd')
    74642
    '''
    try: return int(findall(b'0x[0-9a-f]+', s)[0], 16)
    except IndexError: return -1
def unpack_many_hex(s: bytes) -> list:
    ''' Extract a list of hex numbers from a bytestring
    >>> unpack_many_hex(b'jfawoa0x1234aokfw 0x123')
    [0x1234a, 0x123]
    '''
    try: return list(map(lambda l: int(l,16), findall(b'0x[0-9a-f]+', s)))
    except IndexError: return []

def offset_to_regex(addr: int) -> str:
    return '.*' + hex(addr)[2:] + '$'

def offset_match(addr: int, offset: int) -> bool:
    return offset is None or bool(search(offset_to_regex(offset), hex(addr)))

def is_wsl() -> bool: return b'Microsoft' in read('/proc/sys/kernel/osrelease') 
# TODO: compress all of theses is_X_address into a... class or something
class AddrChecker():
    ''''''
    def __call__(self, addr: int) -> bool:
        '''Check if `addr` looks like _any_ reasonable paged address.'''
        return any(f(addr) for f in [self.stack, self.libc, self.PIE])

    def _generic(_, addr: int, regex_type: str):
        ADDRESS_REGEX = {
            'PIE': {'amd64': '0x5[56][0-9a-f]{10}', 'i386': '0x5[56][0-9a-f]{6}'},
            'stack': {'amd64': '0x7ff.*', 'i386': '0xff.*'},
            'libc': {'amd64':'0x7f.*', 'i386': '0xf7.*'},
            'canary': defaultdict(lambda: '.*00'),
            'base': defaultdict(lambda: '.*000$')
        }
        return addr > 0 and search(ADDRESS_REGEX[regex_type][context.arch], hex(addr))

    def PIE(self, addr: int) -> bool:
        '''Heuristic for _potential_ PIE addresses '''
        if is_wsl():
            log.warn("The memory mappings for wsl1 are not always congruent"+\
                    " with that of normal linux. Some things may break.")
        return self._generic(addr, 'PIE')

    def canary(self, addr: int) -> bool:
        '''Heuristic for _potential_ canary values'''
        return addr % 0x100 == 0 and pack(addr).count(b'\x00') < 3 and not self(addr)

    def stack(self, addr: int) -> bool:
        '''Heuristic for _potential_ stack addresses'''
        return self._generic(addr, 'stack')

    def base(self, addr: int) -> bool:
        '''Heuristic for _potential_ base addresses'''
        return self._generic(addr, 'base')

    def libc(self, addr: int) -> bool:
        '''Heuristic for _potential_ libc addresses'''
        return self._generic(addr, 'libc') and not self.stack(addr)

is_addr = AddrChecker()

# Graveyard of depreciated functions
"""
def extract_first_bytes(s: bytes, n: int) -> int:
def extract_all_bytes(s: bytes, n: int) -> list:
    ''' Extract a list of unpacked bytes of length `n` from a bytestring
    Note that the list will truncate the bytestring to be divisible by `s`'''
    return map(lambda s: unpack(s,n*8), group(n, s, 'drop'))
def extract_all_hex(s: bytes) -> list:
def extract_first_hex(s: bytes) -> int:
def is_PIE_address(addr: int) -> bool:
def is_address(addr: int) -> bool:
def is_canary(addr: int) -> bool:
def is_stack_address(addr: int) -> bool:
def is_base_address(addr: int) -> bool:
def is_libc_address(addr: int) -> bool:
"""