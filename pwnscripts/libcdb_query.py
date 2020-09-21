'''Reinventing the wheel for LibcSearcher
See examples/, or try starting with libc().
'''
from re import search
from glob import glob
from typing import Dict
from os import path, system
from subprocess import check_output, CalledProcessError
from pwnlib.ui import options
from pwnlib.log import getLogger
from pwnlib.elf.elf import ELF
from pwnlib.util.misc import which
from pwnlib.util.lists import concat
from pwnlib.tubes.process import process
from pwnscripts.string_checks import is_base_address
from pwnscripts import config
from pwnscripts.context import context
log = getLogger('pwnlib.exploit')
# Helpfully taken from the one_gadget README.md
def _one_gadget(filename):
    return list(map(int, check_output(['one_gadget', '--raw', filename]).split(b' ')))

# BEGIN DEPRECATED
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
    log.warn('libc_find() is Deprecated! Try using libc_database().libc_find().')

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
# END DEPRECATED

def _db(db_dir: str):
    '''Simple wrapper to return a libc_database() object for a given
    `db_dir`, using context.libc_database if db_dir is None.
    Not meant for public usage. Will raise IOError if everything is None.
    >>> _db('inexistant_dir')
    Traceback (most recent call last):
    ...
    OSError: ...
    >>> _db('libc-database')
    <pwnscripts.libcdb_query.libc_database object at 0x7ffffffffff0>
    >>> context.libc_database = 'libc-database'
    >>> _db(None)
    <pwnscripts.libcdb_query.libc_database object at 0x7fffbffffff0>
    '''
    if db_dir is not None:  # Always use db_dir if possible
        return libc_database(db_dir)
    elif context.libc_database is not None: # If not None
        return context.libc_database
    else:
        raise IOError("No libc-database found!\n"
        "Either provide db_dir='/path/to/libc-database', or "
        "set context.libc_database = '/path/to/libc-database'.")

# TODO: allow db_dir=None by querying from https://libc.rip API.
class libc_database():
    '''An object to represent an existing libc-database stored locally.
    All libc-database functions are available as object methods.
    
    >>> context.libc_database = 'libc-database'
    >>> print( context.libc_database.dump().decode() )
    offset___libc_start_main_ret = 0x21b97
    offset_system = 0x000000000004f440
    offset_dup2 = 0x00000000001109a0
    offset_read = 0x0000000000110070
    offset_write = 0x0000000000110140
    offset_str_bin_sh = 0x1b3e9a
    '''
    def __init__(self, db_dir: str):
        '''initialise libc_database() from an existing database at `db_dir`.
        Raises IOError if db_dir is not a directory.'''
        if path.isdir(db_dir):
            self.db_dir = path.abspath(db_dir)
        else:
            raise IOError("Directory " + repr(db_dir) + " does not exist!"
            " libc_database() requires a valid /path/to/libc-database.")

    def libc_find(self, leaks: Dict[str,int]):
        '''identify a libc id from a `dict` of leaked addresses,
        returning its libc() representation on success.
        Raises IndexError if a single libc id is not isolated.

        Arguments:
            `leaks`: dict with key-pairs of symbol_name:addr
        
        Returns:
            a `libc()` object with `address` set in accordance with the
            leaked addresses provided in `leaks`.
        >>> db = context.libc_database = '/path/to/libc-database'
        >>> context.libc = db.libc_find({'printf': 0x7fff00064e80})
        Traceback (most recent call last):
        File "<stdin>", line 1, in <module>
        File "/path/to/pwnscripts/pwnscripts/libcdb_query.py", line 234, in libc_find
            raise IndexError("incorrect number of libcs identified: %d" % len(found))
        IndexError: incorrect number of libcs identified: 4
        >>> context.libc = db.libc_find({'printf': 0x7fff00064e80, 'strstr': 0x7fff0009eb20})
        [*] b'found libc! id: libc6_2.27-3ubuntu1_amd64'
        [*] '/path/to/pwnscripts/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
            Arch:     amd64-64-little
            RELRO:    Partial RELRO
            Stack:    Canary found
            NX:       NX enabled
            PIE:      PIE enabled
        >>> hex(context.libc.address)
        0x7fff00000000
        '''
        args = concat([(k,hex(v)) for k,v in leaks.items()])
        found = self.find(*args).strip().split(b'\n')

        if len(found) == 1: # if a single libc was isolated
            # NOTE: assuming ./find output format is "<url> (<id>)". 
            # NOTE (continued): this behaviour has changed in the past!
            libcid = found[0].split(b'(')[-1][:-1]  
            log.info(b'found libc! id: ' + libcid)
            lib = libc(db=self, id=libcid.decode('utf-8'))
            # Also help to calculate self.base
            a_func, an_addr = list(leaks.items())[0]
            lib.calc_base(a_func, an_addr)
            return lib
        raise IndexError("incorrect number of libcs identified: %d" % len(found))

    def id(self, binary: str) -> str:
        '''Identify a libc.so binary, and auto-add it if it doesn't exist

        Arguments: a path to a libc binary

        Returns: a libc id that must exist
        '''
        try:    # EXPECTED OUTPUT: b'<identifier>\n'
            return self.identify(binary)[:-1].decode()
        except CalledProcessError:  # assume that a hitherto-unknown libc binary was given
            log.warn("the file " + repr(binary) + " was not found"
                    " in the libc-database. Assuming it is a libc file.")
            output = self.add(binary).decode()                  # Intentionally uncatch errors
            return search('local-[0-9a-f]+', output).group(0)   #!assumes self.binary doesn't match!

    def __getattr__(self, attr):
        '''Generic wrapper to subprocess.check_output() to enable running
        all of the libc-database scripts as libc_database() attributes.
        e.g.
        >>> output = context.libc_database.dump('libc6_2.27-3ubuntu1_amd64')
        >>> print(output.decode())
        offset___libc_start_main_ret = 0x21b97
        offset_system = 0x000000000004f440
        offset_dup2 = 0x00000000001109a0
        offset_read = 0x0000000000110070
        offset_write = 0x0000000000110140
        offset_str_bin_sh = 0x1b3e9a
        '''
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
    def __init__(self, binary: str=None, id: str=None, *, db_dir: str=None, db=None):
        '''initialise a libc database using `binary`="/path/to/libc.so.6", or with identifier `id`,
        given the location `db_dir` of a local libc-database, or a libc_database() instance, `db`.
        If both `db` and `db_dir` is None, libc() will try using `context.libc_database`.

        >>> lib = libc(db_dir='/path/to/libc-database', id='libc6_2.27-3ubuntu1_amd64')
        or alternatively,
        >>> context.libc_database = '/path/to/libc-database'
        >>> context.libc = './libc.so.6'

        Arguments:
            `binary`:
                a filepath to a libc binary.

            `id`:
                a libc-database identifier for the binary
            
            `db_dir`:
                a filepath to a libc-database.

            `db`:
                an existing libc_database() object.
                This will take precedence over `db_dir`, if (for whatever reason)
                both happen to be provided.
        
        Returns:
            a libc() object.
        '''
        # init a local libc-database
        if db is None:
            self.db = _db(db_dir)
        elif type(db) == libc_database:
            self.db = db
        else:
            raise ValueError("`db`="+repr(db)+"does not seem to be an instance of libc_database().")
        
        if binary is not None:
            id = self.db.id(binary)
        if id is not None:  # Assume the id is valid
            self.local = id[:6] == 'local-'
            self.id = id
            self.libpath = path.join(self.db.db_dir, 'db', id)
            self.binary = self.libpath + '.so'
            super().__init__(self.binary, checksec=False)   # Call ELF() on self.binary
            self.__id_init__()
        else:
            raise ValueError('libc(...) requires binary="/path/to/libc.so.6"'+\
                             ' or identifer="<libc identifier>" as an argument')
    
    def __id_init__(self):
        # load up all library symbols; adds things like str_bin_sh uncaught by ELF()
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
        return self.one_gadget[option] + self.address

    def dir(self) -> str:
        '''Get the '/path/to/libc-database/libs/self.id' for this libc
        Will raise ValueError if the libc is a locally imported libc
        '''
        # Why use a method instead of an __init__ defined property?
        # Some users might not appreciate needing to ./download every library they use.
        if self.local:
            raise ValueError("'local-*' libc can never have a libs/ directory!")
        lib_dir = path.join(self.db.db_dir, 'libs', self.id)
        if not path.isdir(lib_dir):     # if lib_dir doesn't exist, but it's not local-*
            log.info('libs/ for id=%r was not found; downloading now' % self.id)
            self.db.download(self.id)   # download it
        return lib_dir

    def run_with(self, binary: ELF, argv=[], *a, **kw) -> process:
        '''Run a `binary` with arguments `argv` using this libc's associated libs/ path.

        Arguments:
            `binary`: This is an ELF(). Please don't try to use a filename like with process().
            `argv`: arguments to be passed 
        '''
        # First, find this libc's ld-linux.so with a glob*.
        lib_dir = self.dir()
        ld_linux_glob = glob(path.join(lib_dir, 'ld-linux*'))
        assert len(ld_linux_glob) == 1   # This should never fail, but in case.
        ld_linux = ld_linux_glob[0] # Guaranteed to exist as a file; barring race conds
        # Next, run the process as ./ld-linux.so --library-path lib_dir binary [ARGS] ...
        log.info('[libc] Running %r with libs in %r!' % (binary.path, lib_dir))
        return process([ld_linux, '--library-path', lib_dir, binary.path]+argv, *a, **kw)