'''An extension of pwnlib.rop.rop.ROP.'''
from typing import Union, Tuple
from pkg_resources import parse_version
from pwnlib import rop, constants, __version__ as PWNLIB_VER
from pwnlib.abi import ABI
from pwnlib.rop.call import Call
from pwnlib.util.packing import flat
from pwnlib.shellcraft import registers
from pwnscripts.context import context

class ROP(rop.rop.ROP):
    '''Extended pwnscripts ROP class
    '''
    class _Pop():
        '''Internal constructor for implementing ROP.pop
        This class is a wrapper, and should not be called outside of ROP().__init__().
        Documentation here is to show examples for ROP.pop (see `pydoc pwnscripts.ROP._Pop`)
        '''
        def __init__(self, rop):
            self.rop = rop
        def __call__(self, regs: dict) -> None:
            '''convinence function to edit a few registers
            Examples:
            >>> rop = ROP("./binary")
            >>> rop.pop({'rax':0x3b, 'rsi': 0, 'rdx': 0})
            >>> print(rop.dump())
            0x0000:         0x44a309 pop rdx; pop rsi; ret
            0x0008:              0x0
            0x0010:              0x0
            0x0018:         0x41e4af pop rax; ret
            0x0020:             0x3b
            '''
            self.rop._chain += [t[0] for t in self.rop.setRegisters(regs)]
        def __getattr__(self, attr):
            '''convinence wrapper to allow .pop.<reg>(v)
            >>> rop = ROP('./binary')
            >>> rop.pop.rdi(1)
            >>> print(rop.dump())
            0x0000:         0x401696 pop rdi; ret
            0x0008:              0x1
            '''
            if attr not in getattr(registers, context.arch):
                raise AttributeError("module 'ROP.pop' has no attribute %r" % attr)
            # else: Register is being set
            return lambda v: self({attr:v})

    class _Syscall():
        '''Internal constructor for implementing ROP.system_call
        This class is a wrapper, and should not be called outside of ROP().__init__().
        Documentation here is to show examples for ROP.system_call (see `pydoc pwnscripts.ROP._Syscall`)
        '''
        def __init__(self, rop):
            self.rop = rop
        def label(self, id: Union[int,str]) -> Tuple[int, str]:
            ''' Convert a syscall identifier to a tuple of (syscall_number, label)'''
            if isinstance(id, int):
                # AFAIK there is no "unresolve" function for pwnlib.constants, so
                # if `id` happens to be an int --- just label with hex number
                label = 'SYS_'+hex(id)
            elif isinstance(id, str):   # Convert id to int
                if len(id) < 4 or id[:4] != 'SYS_': # Prepend 'SYS_' to id if not present
                    id = 'SYS_' + id
                id = getattr(constants, label:=id)
            else:
                raise TypeError('%s: id=%r is not int/str' % (self, id))
            return (id, label)
        def __getattr__(self, syscall: str):
            ''' Allow for r.system_call.read(...) -> r.system_call('read', ...)
            >>> context.binary = './binary32'   #implicit arch reset here
            >>> r = ROP(context.binary)
            >>> r.system_call.read([0, context.binary.bss(), 50])
            >>> print(r.dump())
            0x0000:         0x44a309 pop rdx; pop rsi; ret
            0x0008:             0x32 [arg3] rdx = 50
            0x0010:         0x4b92e0 [arg2] rsi = 4952800
            0x0018:         0x41e4af pop rax; ret
            0x0020:              0x0 [arg0] rax = SYS_read
            0x0028:         0x401696 pop rdi; ret
            0x0030:              0x0 [arg1] rdi = 0
            0x0038:         0x4022b4 SYS_read
            '''
            return lambda *c, **v: self(syscall, *c, **v)
        def __call__(self, id: Union[int,str], args: list, ret: bool=False) -> None:
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

            Arguments:
                `id`: integer syscall number OR string identifier for the syscall
                    if int: integer is used directly as register value for syscall
                    if str: The syscall number will be resolved with `pwnlib.constants`.
                `args`: arguments to the syscall
                `ret`: Specifically use a 'syscall; ret' gadget for syscalls (instead of 'syscall')
                    `ret` WILL NOT WORK unless you have the dev verison of pwntools installed.
            
            Returns:
                Nothing. Will raise errors if things go wrong.
            '''
            # get the syscall gadget
            if ret:
                if parse_version(PWNLIB_VER) < parse_version('4.4.0dev0'):
                    raise NotImplementedError('"syscall; ret" gadgets are only available on the '
                    'latest version of pwntools.')
                # pwnlib.rop.srop.syscall_instructions == {'amd64': ['syscall'], 'arm': ['svc 0'], ...}
                syscall = self.rop.find_gadget([rop.srop.syscall_instructions[context.arch][0], 'ret'])
            else:   # Can lazily use ROP's __getattr__ here
                syscall = self.rop.syscall
            if syscall is None:
                raise AttributeError("ROP unable to find syscall gadget")
            
            # write the syscall
            id, label = self.label(id)
            self.rop.raw(Call(label, syscall.address, [id] + args, ABI.syscall()))

    def __init__(self, *a, **kw):
        self.pop = ROP._Pop(self)
        self.system_call = ROP._Syscall(self)
        super().__init__(*a, **kw)
    def chain(self, base=None) -> bytes:
        '''Build the ROP chain (and use a `base` if given)

        Returns:
            str containing raw ROP bytes
        '''
        return flat(self.build(base=base))
    def dump(self, base=None) -> str:
        '''Dump the ROP chain in an easy-to-read manner
        Optional `base` argument to change the ROP base'''
        return self.build(base=base).dump()
