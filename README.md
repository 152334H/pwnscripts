# pwnscripts
[![Tests](https://github.com/152334H/pwnscripts/workflows/Python%20package/badge.svg)](https://github.com/152334H/pwnscripts/actions)
[![PyPI package](https://badge.fury.io/py/pwnscripts.svg)](https://pypi.org/project/pwnscripts/)
[![Python](https://img.shields.io/pypi/pyversions/pwnscripts)](https://www.python.org/downloads/)

Very simple script(s) to hasten binary exploit creation. To use, `pip install pwnscripts` OR run
```bash
git clone https://github.com/152334H/pwnscripts
cd pwnscripts
pip install -e .
```
and replace `from pwn import *` with `from pwnscripts import *`, e.g.

```python
from pwnscripts import *
context.binary = './my_challenge'
...
```

Additionally, the `libc_database()` extension of pwnscripts requires the [libc-database](https://github.com/niklasb/libc-database).

You might want to look at some of the examples in `user_tests_and_examples.py`.

## Features

Pwnscripts has a number of different features.

### Libc
Things like [LibcSearcher](https://github.com/lieanu/LibcSearcher) have always felt incomplete.

Pwnscripts provides two libc classes: `libc()` and `libc_database()`. The easiest way to start with both is with `context`:
```python
context.libc_database = '/path/to/libc-database'  # https://github.com/niklasb/libc-database
context.libc = '/path/to/pwnscripts/examples/libc.so.6'
```
Anything you can run with `./libc-database/[executable]` is available as a `libc_database()` method: 
```python
>>> context.libc_database.dump('libc6_2.27-3ubuntu1_amd64')
b'offset___libc_start_main_ret = 0x21b97\noffset_system = 0x000000000004f440\noffset_dup2 = 0x00000000001109a0\noffset_read = 0x0000000000110070\noffset_write = 0x0000000000110140\noffset_str_bin_sh = 0x1b3e9a\n'
>>> output = context.libc_database.add()
>>> print(output.decode())
Adding local libc /path/to/pwnscripts/examples/libc.so.6 (id local-18292bd12d37bfaf58e8dded9db7f1f5da1192cb  /path/to/pwnscripts/examples/libc.so.6)
  -> Writing libc /path/to/pwnscripts/examples/libc.so.6 to db/local-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so
  -> Writing symbols to db/local-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.symbols
  -> Writing version info
```
`libc_database()` also has a few additional methods; you can look at the [tests](https://github.com/152334H/pwnscripts/blob/master/test_automated.py) and [examples](https://github.com/152334H/pwnscripts/blob/master/user_tests_and_examples.py) and documentation to see.

---

The `libc()` object is a subclass of pwntools' `pwnlib.elf.elf.ELF()`. It starts off with a base address of `0`, but you can change that to match a remote executable by providing it with leaked addresses:
```python
>>> context.libc.calc_base('scanf', 0x7fffa3b8b040) # Provide a leaked address to libc
>>> context.libc.address
0x7fffa3b10000
>>> context.libc.symbols['str_bin_sh']  # Symbols from libc-database are stored in context.libc
0x7fffa3cc3e9a
```

`pwnscripts` is smart about `context.binary`: if `context.libc` is set, `context.binary.process()` will run with that libc version:
```bash
$ gcc -x c - <<< 'int main(){printf("%p\n", printf);}'
$ python3.8
>>> from pwnscripts import *
>>> context.log_level = 'warn'
>>> context.libc_database = 'libc-database'
>>> context.binary = './a.out'
>>> context.libc = 'libc6_2.31-0ubuntu9_amd64'
>>> context.binary.process().recvline()
b'0x7fa0f3c3fe10\n'   # printf 0000000000064e10
>>> context.libc = 'libc6_2.24-11+deb9u4_amd64'
>>> context.binary.process().recvline()
b'0x7fb99b69e190\n'   # printf 000000000004f190
```

`libc()` provides `one_gadget` integration in the form of an interactive selection:
```python
>>> context.libc.select_gadget()
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
 [?] choose the gadget to use: 
       1) 0x4f2c5
       2) 0x4f322
       3) 0x10a38c
     Choice 
```
You're free to shut up the interactive menu by giving `.select_gadget()` an argument:
```python
>>> context.libc.select_gadget(1)
0x4f322
```
More features exist, but this is already too long.

### Format string exploitation
pwnscripts provides the `fsb` module, which can be split further into:
  * `.find_offset`: helper functions to bruteforce wanted printf offsets.

    If you've ever found yourself spamming `%n$llx` into a terminal: this module will automate away all that. Take a look at the [example code](test_automated.py) to see how.

    This already partially exists as a feature in pwntools (see `pwnlib.fmtstr.FmtStr`), but pwnscripts expands functionality by having bruteforcers for other important printf offsets, including
    1. `canary`s, for defeating stack protectors,
    2. `stack` addresses, to make leaking a stack pointer much easier,
    3. other things like `code` addresses with more niche purposes
  * `.leak`: a simple two-function module to make leaking values with `%s` a lot easier.

    The simple idea is that you get a payload to leak printf values:
    ```python
    offset = fsb.find_offset.buffer(...) # == 6
    payload = fsb.leak.deref_payload(offset, [0x400123, 0x600123])
    print(payload)  # b'^^%10$s||%11$s$$#\x01@\x00#\x01`\x00'
    ```
    And after sending the payload, extract the values with a helper function:
    ```python
    r = remote(...)
    r.sendline(payload)
    print(fsb.leak.deref_extractor(r.recvline()))  # [b'\x80N\x03p\x94\x7f', b' \xeb\x04p\x94\x7f']
    ```
### Minor features
Pwnscripts also comes with a few minor extensions and functions:
* `ROP`: an extension of `pwnlib.rop.rop.ROP`. Core feature is to simplify ROP building outside of SIGROP:
  ```python
  >>> context.arch = 'amd64'
  >>> r = ROP('./binary')
  >>> r.system_call.execve(['/bin/sh',0,0])
  >>> print(r.dump())
    0x0000:         0x44a309 pop rdx; pop rsi; ret
    0x0008:              0x0 [arg3] rdx = 0
    0x0010:              0x0 [arg2] rsi = 0
    0x0018:         0x41e4af pop rax; ret
    0x0020:             0x3b [arg0] rax = SYS_execve
    0x0028:         0x401696 pop rdi; ret
    0x0030:             0x40 [arg1] rdi = AppendedArgument(['/bin/sh'], 0x0)
    0x0038:         0x4022b4 SYS_execve
    0x0040:   b'/bin/sh\x00'
    ```
 * other unlisted features in development

Proper examples for `pwnscripts` are available in `examples/` and `user_tests_and_examples.py`.
## I tried using it; it doesn't work!

File in an [issue](https://github.com/152334H/pwnscripts/issues), if you can. With a single-digit userbase, it's hard to guess what might go wrong, but potentially:
 * pwnscripts is broken
 * Python is outdated (try python3.8+)
 * libc-database is not properly installed/initalised (did you run ./get?)
 * The binary provided is neither i386 or amd64; other architectures are mostly ignored (out of necessity)
 * The challenge is amd64, but `context.arch` wasn't set to `amd64`

     * Set `context.binary` appropriately, or set `context.arch` manually if no binary is given
 * Other unknown reasons. Try making a pull-request if you're interested.

## Updates

**v0.5.0** - Breaking Behavior
*Changes*
 * `string_checks` has been refactored:
   * `string_checks` itself is now named `util`
   * `is_X_address` functions have been renamed to `is_addr.X`
   * `extract_*` functions have been renamed to `unpack_*`
 * `libc_db()` from v0.1 is now fully removed from pwnscripts.
 * bugfixes for fsb.leak module

**v0.4.0** - ROP Update

*New*
 * `ROP.pop` && `ROP.system_call` overhaul
   * Use `ROP.pop.<reg>(value)` to pop a single register ASAP
   * `ROP.system_call.<func>(args)` is a similar shortcut
   * `ROP.system_call(id, ...)` will now accept a `str` for `id` (where `id` is the name of the syscall)
   * These changes mean that `help()` is essentially broken for these functions. In lieu of that, more docstrings!
   * Added a test for these changes

*Internal changes*
 * Some of the TODOs have been extended with short outlines

**v0.3.1** - Documentation; very minor README.md edit.

**v0.3.0** - libc update

*New*
 * Use `context.libc.run_with()` to run an `ELF()` with a specific libc version.
   * This is reliant on `ld-linux.so`; no more `LD_PRELOAD` segfaults!
   * `context.binary` is aware of `context.libc`, and will automagically use `.run_with()` where possible.
   * Added `context.libc.dir()` to get the `/path/to/libc-database/libs/libc.id/`.
   * Tests have been added for all of these things
 * `ELF` now has an `.ldd_libs()` method to get a list of libs used by a binary on wsl.
 * `rop.system_call()` can now search for `'syscall; ret'` instructions.
   * This is dependent on pwntools-dev

No bugfixes come with this version.

**v0.2.1** - Hotfix: `libc.select_gadget()` will return with the correct `libc.address` adjusted value

**v0.2.0** - libc-database update

*New features*
 * `pwnlib.context.context` is now extended for pwnscripts: `context.libc` and `context.libc_database` have been added as extensions.
 * `pwnscripts.libcdb_query` has undergone a revamp:
     * Two new classes have been created: `libc_database()` and `libc()`.
     * `libc()` is the replacement for `libc_db()`, and inherits from `pwnlib.elf.elf.ELF` to simplify libc offset calculation.
     * `libc_database()` is a class to represent an existing installation of the [`libc-database`](https://github.com/niklasb/libc-database)
   
   The older `libc_db()` class (and the associated `libc_find()`) will remain as deprecated features for the time being.

*Bugfixes and internal changes*
 * Internal code: removal of `attrib_set_to()` & replacement with `context.local` internally
 * Tests & examples have been pruned to ensure that neither file has copied examples from the other.
 * More error catching for libcdb_query.py
 * Lots and lots of documentation + tests


**v0.1.0** - Initial release

pwnscripts is out of pre-alpha, and will follow [Semantic Versioning](https://semver.org/) where possible.

**20-09**

Begin following PEP 440

NEW: `fsb.find_offset` extended with offset-matching searches.

NEW: `pwntools`' `ROP` class has been extended with new features.

libc_db() can (must) now be initialised with either a filepath to a libc.so.6 `binary`, or with an identifier `id`. 

This breaks the original behaviour of allowing e.g. `libc_db('/path/to/libc-database', '<identifier>')`

**20-08.1**

NEW: printf() functions are now kept under the `pwnscripts.fsb` module. Older prototypes for find_printf_* functions remain available for now.

Addition of a lot of docstrings, plus example binaries.

**20-08**

Added a lot of whitespace.

Added a wrapper object for libc-database: the `libc_db` object. This is mostly a reinvention of tools like `LibcSearcher`, although I have yet to see another project tack on `one_gadget` searching, which is a (hacky) feature added for `libc_db`.

Minor adjustments to *printf*. Logging is suppressed for offset bruteforcing; new feature to make a leak payload.

Extended readme.

**20-06**

Added module packaging stuff, so that `pip install -e .` works

You can now see a test example of this library in `test.py`.

Gradual updates expected as I continue to do pwn.
