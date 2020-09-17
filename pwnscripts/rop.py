'''An extension of pwnlib.rop.rop.ROP.'''
from pwnlib import rop
from pwnlib.rop.call import Call
from pwnlib.util.packing import flat
from pwnscripts.context import context
class ROP(rop.rop.ROP):
    def chain(self, base=None):
        '''Build the ROP chain (and use a `base` if given)

        Returns:
            str containing raw ROP bytes
        '''
        return flat(self.build(base=base))
    def dump(self, base=None):
        '''Dump the ROP chain in an easy-to-read manner
        Optional `base` argument to change the ROP base'''
        return self.build(base=base).dump()
    def system_call(self, num: int, args: list):
        '''Making system calls without the massive overhead of SIGROP
        >>> context.arch = 'amd64'
        >>> r = ROP('./binary')
        >>> r.system_call(0x3b, ['/bin/sh', 0, 0])
        >>> print(r.dump())
        0x0000:         0x41e4af pop rax; ret
        0x0008:             0x3b
        0x0010:         0x44a309 pop rdx; pop rsi; ret
        0x0018:              0x0 [arg2] rdx = 0
        0x0020:              0x0 [arg1] rsi = 0
        0x0028:         0x401696 pop rdi; ret
        0x0030:             0x40 [arg0] rdi = AppendedArgument(['/bin/sh'], 0x0)
        0x0038:         0x4022b4 syscall
        0x0040:   b'/bin/sh\x00'
        '''
        if context.arch != 'amd64':
            raise NotImplementedError("syscall_call() is only implemented for amd64 right now")
        if self.syscall is None:
            raise AttributeError("ROP unable to find syscall gadget")
        self.pop({'rax': num})
        self.raw(Call('syscall', self.syscall.address, args))
    def pop(self, registers: dict):
        '''convinence function to edit a few registers
        >>> rop = ROP("./binary")
        >>> rop.pop({'rax':0x3b, 'rsi': 0, 'rdx': 0})
        >>> print(rop.dump())
        0x0000:         0x44a309 pop rdx; pop rsi; ret
        0x0008:              0x0
        0x0010:              0x0
        0x0018:         0x41e4af pop rax; ret
        0x0020:             0x3b
        '''
        self._chain += [t[0] for t in self.setRegisters(registers)]
