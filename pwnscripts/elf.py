'''Override for pwnlib's ELF'''
from os import path
from subprocess import check_output
import pwnlib
from pwnscripts.context import context
from pwnscripts.util import is_addr
__all__ = ['ELF', 'remote']

class _SymbolDict(pwnlib.elf.elf.dotdict):
    def __init__(self, *args, owner, **kwargs):
        # owner: pwnscripts.elf.ELF
        super().__init__(*args, **kwargs)
        self._owner = owner

    def __setitem__(self, key: str, value: int):
        '''overridden dict for ELF.symbols.
        Expected behaviour:
        >>> ELF.symbols
        {'test': 0x128}
        >>> ELF.symbols['other'] = 0x9125   # 'other' not in ELF.symbols
        >>> ELF.symbols
        {'test': 0x128, 'other': 0x9125}
        >>> ELF.symbols['test'] = 0x7fff12345128 # 'test' in ELF.symbols
        >>> ELF.symbols
        {'test': 0x7fff12345128, 'other': 0x7fff1234e125}
        '''
        if key in self:
            self._owner.address = value-self[key] # check base address
            # note that this implicitly resets self.symbols to a dotdict()...
            if not is_addr.base(self._owner.address):
                raise ValueError('pwnscripts.ELF: faulty base address (%s) calculated '
                'from symbol %r (address %s)' % (hex(self._owner.address), key, hex(value)))
            # ...meaning that __setitem__ will not recurse here!
            self._owner.symbols[key] = value
            self._owner.symbols = _SymbolDict(self._owner.symbols, owner=self._owner)
        else:
            super().__setitem__(key, value)
class ELF(pwnlib.elf.elf.ELF):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.symbols = _SymbolDict(self.symbols, owner=self)
    def calc_base(self, symbol: str, addr: int) -> int:
        '''Given the ASLR address of a symbol,
        calculate (and return) the randomised base address.
        This will also silently set self.address to be the base -
        further queries to self.symbols[] will be adjusted to match.

        Arguments:
            `symbol`: the name of the function/symbol found in ELF.symbols
                e.g. read, __libc_start_main, fgets
            `addr`: the actual ASLR address assigned to the symbol
                for the current active session
                e.g. 0x7f1234567890
        Returns: the ASLR base address of the ELF (for the active session)
        '''
        self.address = 0    # reset self.address if it is currently set
        self.address = addr - self.symbols[symbol]
        assert is_addr.base(self.address)   # check that base addr is reasonable
        return self.address

    def ldd_libs(self) -> list:
        '''ELF.libs fails on wsl. This function is here for that purpose.
        Returns: list of library basenames detected by ldd.
        '''
        ldd = check_output(['ldd', self.path]).decode()
        libpaths = pwnlib.util.misc.parse_ldd_output(ldd).keys()
        return list(map(path.basename, libpaths))

    def process(self, argv=[], *a, **kw) -> pwnlib.tubes.process.process:
        '''pwnscripts overridden .process() method
        If `context.libc` is set, process() will run
            context.libc.run_with(self, argv, *a, **kw)
        Otherwise, the original pwntools' ELF.process() is called.

        Returns:
            pwnlib.tubes.process.process() object
        '''
        context._local = True # Make sure to update .is_local
        if context.libc is None:
            return super().process(argv, *a, **kw)
        return context.libc.run_with(self, argv, *a, **kw)
    
    def from_assembly(asm, *a, **kw): # cheap override
        return ELF(pwnlib.asm.make_elf_from_assembly(asm, *a, **kw))

# Temp: put remote() override here until there is a better file to put it in
from pwnlib import tubes
class remote(tubes.remote.remote):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        context._local = False