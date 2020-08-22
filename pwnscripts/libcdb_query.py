from os import path, system
from pwnscripts.string_checks import *
# Helpfully taken from the one_gadget README.md
import subprocess
def one_gadget(filename):
    return list(map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(b' ')))

class libc_db():
    def __init__(self, db_dir:str, identifier: str):
        self.libpath = path.join(db_dir, 'db', identifier)
        self.__dict__.update({k: v for k, v in locals().items() if k != 'self'}) #magic
        with open(self.libpath+'.symbols') as f:
            self.symbols = dict(l.split() for l in f.readlines())
        for k in self.symbols: self.symbols[k] = int(self.symbols[k],16)
        #one_gadget
        if system('which one_gadget > /dev/null'):
            log.info('one_gadget does not appear to exist in PATH. ignoring.')
            self.one_gadget = None
        else:
            self.one_gadget = one_gadget(self.libpath+'.so')

    def calc_base(self, symbol: str, addr: int):
        self.base = addr - self.symbols[symbol]
        assert is_base_address(self.base)   # check that base addr is reasonable
        return self.base

    def select_gadget(self):
        assert self.one_gadget is not None
        system("one_gadget '" + self.libpath+".so'")
        #TODO: find a way to do this that looks less hacky
        option = int(input('choose the gadget to use (0-indexed): '))
        assert 0 <= option < len(self.one_gadget)
        return self.one_gadget[option]

