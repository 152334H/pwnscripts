'''Reinventing the wheel for LibcSearcher
See examples/, or try starting with libc_db().
'''
from re import search
from typing import Dict
from os import path, system
from subprocess import check_output, CalledProcessError
from pwnlib.ui import options
from pwnlib.log import getLogger
from pwnlib.elf.elf import ELF
from pwnlib.util.misc import which
from pwnlib.util.lists import concat
from pwnscripts.string_checks import is_base_address
from pwnscripts import config
log = getLogger('pwnlib.exploit')
# Helpfully taken from the one_gadget README.md
def _one_gadget(filename):
    return list(map(int, check_output(['one_gadget', '--raw', filename]).split(b' ')))

'''TODO
"Run with this libc" function? (see: pwnlib.util.misc.parse_ldd_output)
'''
'''TODO
Make use of pwntools' ELF functionality for simplicity.
We should inherit from pwnlib.elf.elf.ELF().
Example:
e = ELF('./libc.so')
puts_addr = ... #leaked
e.address = puts_addr-e.symbols['puts']
# After here, e.symbols[] works with base automagically!
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
        # NOTE: assuming ./find output format is "<url> (<id>)". 
        # NOTE (continued): this behaviour has changed in the past!
        libcid = found[0].split(b'(')[-1][:-1]  
        log.info(b'found libc! id: ' + libcid)
        db = libc_db(db_dir, id=libcid.decode('utf-8'))
        # Also help to calculate self.base
        a_func, an_addr = list(leaks.items())[0]
        db.calc_base(a_func, an_addr)
        return db
    raise IndexError("incorrect number of libcs identified: %d" % len(found))

class libc_db():
    def __init__(self, db_dir: str, *, binary: str=None, id: str=None):
        '''initialise a libc database using identifier `id`,
        or with `binary`="./path/to/libc.so.6",
        given the location `db_dir` of a local libc-database.

        >>> db = libcdb('/path/to/libc-database', id='libc6_2.27-3ubuntu1_amd64')
        >>> db = libcdb('/path/to/libc-database', binary='./libc.so.6')
        '''
        log.warn('libc_db() is depreciated. Try to use libc() instead.')
        self.db_dir = db_dir
        if id is not None:
            self.id = id
            self.__id_init__()
        elif binary is not None:
            self.binary = binary
            self.__binary_init__()
        else:
            raise ValueError('libc_db(...) requires binary="/path/to/libc.so.6"'+\
                             ' or identifer="<libc identifier>" as an argument')
    
    def __binary_init__(self):
        identify = path.join(self.db_dir, 'identify')
        if not path.isfile(self.binary):
            raise IOError('%r does not appear to be a libc-database/ folder.' % self.db_dir)
        # check_output raises error on non-zero exit, so no other checks are needed.
        try:    # EXPECTED OUTPUT: b'<identifier>\n'
            self.id = check_output([identify, self.binary])[:-1].decode()
        except CalledProcessError:  # assume that a hitherto-unknown libc binary was given
            log.warn(''.join(("the file %r was not found" % self.binary,
                        " in the libc-database. Assuming it is a libc file.")))
            add = path.join(self.db_dir, 'add')
            output = check_output([add, self.binary]).decode()  # Intentionally uncatch errors
            self.id = search('local-[0-9a-f]+', output).group(0)#!assumes self.binary doesn't match!
        self.__id_init__()
    
    def __id_init__(self):
        self.libpath = path.join(self.db_dir, 'db', self.id)
        # load up all library symbols
        with open(self.libpath+'.symbols') as f:    # Weird thing: this breaks if 'rb' is used.
            self.symbols = dict(l.split() for l in f.readlines())
        for k in self.symbols: self.symbols[k] = int(self.symbols[k], 16)
        
        # load up one_gadget offsets in advance
        if which('one_gadget') is None:
            log.info('one_gadget does not appear to exist in PATH. ignoring.')
            self.one_gadget = None
        else:
            self.one_gadget = _one_gadget(self.libpath+'.so')

    def calc_base(self, symbol: str, addr: int) -> int:
        '''Given the ASLR address of a libc function,
        calculate (and return) the randomised base address
        
        Arguments:
            `symbol`: the name of the function/symbol found in libc
                e.g. read, __libc_start_main, fgets
            `addr`: the actual ASLR address assigned to the libc symbol
                for the current active session
                e.g. 0x7f1234567890
        Returns: the ASLR base address of libc (for the active session)
        '''
        
        self.base = addr - self.symbols[symbol]
        assert is_base_address(self.base)   # check that base addr is reasonable
        return self.base

    def select_gadget(self, option: int=None) -> int:
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
        if option is None:
            system("one_gadget '" + self.libpath+".so'")
            option = int(options('choose the gadget to use: ', list(map(hex,self.one_gadget))))
        assert 0 <= option < len(self.one_gadget)
        return self.one_gadget[option]

class libc_database():  # python wrapper for libc-database functions
    def __init__(self, db_dir: str=None):
        if db_dir is not None: self.db_dir = db_dir
        elif config.LIBC_DB_DIR is not None: self.db_dir = config.LIBC_DB_DIR
        else: raise ValueError('libc_database(...) requires db_dir="/path/to/libc-database" as arg')

    def id(self, binary: str) -> str:
        '''Identify a libc.so binary, and auto-add it if it doesn't exist

        Arguments: a path to a libc binary

        Returns: a libc id that must exist
        '''
        try:    # EXPECTED OUTPUT: b'<identifier>\n'
            return self.identify(binary)[:-1].decode()
        except CalledProcessError:  # assume that a hitherto-unknown libc binary was given
            log.warn(''.join(("the file %r was not found" % binary,
                        " in the libc-database. Assuming it is a libc file.")))
            add = path.join(self.db_dir, 'add')
            output = check_output([add, binary]).decode()       # Intentionally uncatch errors
            return search('local-[0-9a-f]+', output).group(0)   #!assumes self.binary doesn't match!

    def __getattr__(self, attr):    # generic function
        def default(*args):
            script = path.join(self.db_dir, attr)
            if not path.isfile(script):
                raise IOError('%r does not appear to be a libc-database/ folder.' % self.db_dir)
            # check_output will raise error on non-zero exit; let it happen
            return check_output([script, *args])
        return default

# Libc() class
class libc(ELF):
    '''Class to handle libc-related things
    Inherrits from pwnlib.elf.elf.ELF, so all non-init methods from ELF
    will be available for this.'''
    def __init__(self, db_dir: str=None, binary: str=None, id: str=None):
        '''initialise a libc database using identifier `id`,
        or with `binary`="./path/to/libc.so.6",
        given the location `db_dir` of a local libc-database.
        If `db_dir` is None, libc() will try using `pwnscripts.config.LIBC_DB_DIR`.

        >>> lib = libc('/path/to/libc-database', id='libc6_2.27-3ubuntu1_amd64')
        >>> lib = libc('/path/to/libc-database', binary='./libc.so.6')
        '''
        self.db = libc_database(db_dir)
        if binary is not None:
            id = self.db.id(binary)
        if id is not None:  # Assume the id is valid
            self.id = id
            self.libpath = path.join(self.db.db_dir, 'db', id)
            self.binary = self.libpath + '.so'
            super().__init__(binary)
            self.__id_init__()
        else:
            raise ValueError('libc(...) requires binary="/path/to/libc.so.6"'+\
                             ' or identifer="<libc identifier>" as an argument')
    
    def __id_init__(self):
        # load up all library symbols; adds things like str_bin_sh
        with open(self.libpath+'.symbols') as f:    # Weird thing: this breaks if 'rb' is used.
            symbols = dict(l.split() for l in f.readlines())
        for k in symbols: self.symbols[k] = int(symbols[k], 16)
        
        # load up one_gadget offsets in advance
        if which('one_gadget') is None:
            log.info('one_gadget does not appear to exist in PATH. ignoring.')
            self.one_gadget = None
        else:
            self.one_gadget = _one_gadget(self.libpath+'.so')

    def calc_base(self, symbol: str, addr: int) -> int:
        '''Given the ASLR address of a libc function,
        calculate (and return) the randomised base address.
        This will also silently set self.address to be the base - 
        further queries to self.symbols[] will be adjusted to match.
        
        Arguments:
            `symbol`: the name of the function/symbol found in libc
                e.g. read, __libc_start_main, fgets
            `addr`: the actual ASLR address assigned to the libc symbol
                for the current active session
                e.g. 0x7f1234567890
        Returns: the ASLR base address of libc (for the active session)
        '''
        
        self.address = addr - self.symbols[symbol]
        assert is_base_address(self.address)   # check that base addr is reasonable
        return self.address

    def select_gadget(self, option: int=None) -> int:
        '''An interactive function to choose a preferred
        one_gadget requirement mid-exploit.
        
        >>> one_gadget = lib.select_gadget()
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
        if option is None:
            system("one_gadget '" + self.libpath+".so'")
            option = int(options('choose the gadget to use: ', list(map(hex,self.one_gadget))))
        assert 0 <= option < len(self.one_gadget)
        return self.one_gadget[option]
