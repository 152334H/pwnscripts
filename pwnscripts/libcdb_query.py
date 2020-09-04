'''Reinventing the wheel for LibcSearcher
See examples/, or try starting with libc_db().
'''
from typing import Dict
from os import path, system
from subprocess import check_output, CalledProcessError
from pwnlib.ui import options
from pwnlib.util.misc import which
from pwnlib.util.lists import concat
from pwnscripts.string_checks import log, is_base_address
# Helpfully taken from the one_gadget README.md
def one_gadget(filename):
    return list(map(int, check_output(['one_gadget', '--raw', filename]).split(b' ')))

'''TODO
"Run with this libc" function? (see: pwnlib.util.misc.parse_ldd_output)
'''

def libc_find(db_dir: str, leaks: Dict[str,int]):
    '''identify a libc id from a `dict` of leaked addresses.
    the `dict` should have key-pairs of func_name:addr
    Will raise IndexError if a single libc id is not isolated.
    
    >>> libc_find('/path/to/libc-database', {'printf': 0x7fff00064e80})
    Traceback (most recent call last):
    File "<stdin>", line 1, in <module>
    File "/path/to/pwnscripts/pwnscripts/libcdb_query.py", line 28, in libc_find
        raise IndexError("incorrect number of libcs identified: %d" % len(found))
    IndexError: incorrect number of libcs identified: 4
    >>> libc_find('/path/to/libc-database', {'printf': 0x7fff00064e80, 'strstr': 0x7fff0009eb20})
    [*] b'found libc! id: libc6_2.27-3ubuntu1_amd64'
    <pwnscripts.libcdb_query.libc_db object at 0x000000000000>
    '''
    
    args = concat([(k,hex(v)) for k,v in leaks.items()])
    found = check_output([path.join(db_dir, 'find'), *args]).strip().split(b'\n')
    
    if len(found) == 1: # if a single libc was isolated
        libcid = found[0].split(b'(')[-1][:-1]  # NOTE: assuming ./find output format is "<url> (<id>)". This behavior has changed in the past.
        log.info(b'found libc! id: ' + libcid)
        db = libc_db(db_dir, id=libcid.decode('utf-8'))
        # Also help to calculate self.base
        a_func, an_addr = list(leaks.items())[0]
        db.calc_base(a_func, an_addr)
        return db
    raise IndexError("incorrect number of libcs identified: %d" % len(found))

class libc_db():
    def __init__(self, db_dir:str, *, binary:str=None, id:str=None):
        '''initialise a libc database using identifier `id`,
        or with `binary`="./path/to/libc.so.6",
        given the location `db_dir` of a local libc-database.

        >>> db = libcdb('/path/to/libc-database', id='libc6_2.27-3ubuntu1_amd64')
        >>> db = libcdb('/path/to/libc-database', binary='./libc.so.6')
        '''
        self.__dict__.update({k: v for k, v in locals().items() if k != 'self'})    # Assign arguments to self.
        if id is not None:
            self.__id_init__()
        elif binary is not None:
            self.__binary_init__()
        else:
            raise ValueError('libc_db(...) requires binary="/path/to/libc.so.6"'+\
                             ' or identifer="<libc identifier>" as an argument')
    
    def __binary_init__(self):
        identify = path.join(self.db_dir, 'identify')
        assert path.isfile(self.binary)
        self.id = check_output([identify, self.binary])[:-1].decode() # EXPECTED OUTPUT: b'<identifier>\n'
        # check_output will raise an error on non-zero exit, so no other sanity checks are needed here.
        self.__id_init__()
    
    def __id_init__(self):
        self.libpath = path.join(self.db_dir, 'db', self.id)
        # load up all library symbols
        with open(self.libpath+'.symbols') as f:    # Weird thing: this breaks if 'rb' is used.
            self.symbols = dict(l.split() for l in f.readlines())
        for k in self.symbols: self.symbols[k] = int(self.symbols[k],16)
        
        # load up one_gadget offsets in advance
        if which('one_gadget') is None:
            log.info('one_gadget does not appear to exist in PATH. ignoring.')
            self.one_gadget = None
        else:
            self.one_gadget = one_gadget(self.libpath+'.so')

    def calc_base(self, symbol: str, addr: int) -> int:
        '''Given the ASLR address of a libc function,
        calculate (and return) the randomised base address
        
        '''
        
        self.base = addr - self.symbols[symbol]
        assert is_base_address(self.base)   # check that base addr is reasonable
        return self.base

    def select_gadget(self) -> int:
        '''An interactive function to choose a preferred
        one_gadget requirement mid-exploit.
        
        >>> one_gadget = db.select_gadget()
        0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
        constraints:
        rsp & 0xf == 0
        rcx == NULL

        0x4f322 execve("/bin/sh", rsp+0x40, environ)
        constraints:
        [rsp+0x40] == NULL

        0x10a38c execve("/bin/sh", rsp+0x70, environ)
        constraints:
        [rsp+0x70] == NULL
        choose the gadget to use (0-indexed): 1
        >>> print(hex(one_gadget))
        0x4f322
        '''

        assert self.one_gadget is not None
        system("one_gadget '" + self.libpath+".so'")
        #TODO: find a way to do this that looks less hacky
        option = int(options('choose the gadget to use: ', list(map(hex,self.one_gadget))))
        assert 0 <= option < len(self.one_gadget)
        return self.one_gadget[option]

