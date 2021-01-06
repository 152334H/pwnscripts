'''Override for pwnlib's ELF'''
from os import path
from subprocess import check_output
import pwnlib
from pwnscripts.context import context
from pwnscripts.util import is_addr
__all__ = ['ELF']

class ELF(pwnlib.elf.elf.ELF):
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
        if context.libc is None:
            return super().process(argv, *a, **kw)
        return context.libc.run_with(self, argv, *a, **kw)
