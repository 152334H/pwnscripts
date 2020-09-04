# pwnscripts
Very simple script(s) to hasten binary exploit creation. To use, run
```
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

You might want to look at some of the examples in `test_all.py`.

## Features

Current features:
  * `fsb.find_offset`: helper functions to bruteforce wanted printf offsets.
    These are generic bruteforcers to find printf offsets to use for format string exploits.
    
    Some of these already exist as features in pwntools (e.g. `fsb.find_offset.buffer`), but other functions are, to my knowledge, unique to `pwnscripts`.
    
  * `libc_db`: a basic class for dealing with the libc-database project. Unlike LibcSearcher (for now), this class has a wrapper to help with finding one_gadgets as well.
    ```python
    db = libc_db('/path/to/libc-database', binary='/path/to/libc.so.6') # e.g. libc6_2.27-3ubuntu1.2_amd64
    one_gadget = db.select_gadget() # Console will prompt for a selection. Behaviour may change.
    ... <insert exploit code to leak libc address here> ...
    # Let's say the libc address of `puts` was leaked as `libc_puts`
    libc_base = db.calc_base('puts', libc_puts)
    ```
    Proper examples available in `examples/` and `test_all.py`.

  * other unlisted features in development

## I tried using it; it doesn't work!

File in an [issue](https://github.com/152334H/pwnscripts/issues), if you can. With a userbase of 1, it's hard to guess what might go wrong, but potentially:
 * pwnscripts is broken
 * Python is outdated (try python3.8+)
 * The challenge is neither i386 or amd64; other architectures aren't implemented (yet).
 * The challenge is amd64, but `context.arch` wasn't set to `amd64`

     * Set `context.binary` appropriately, or set `context.arch` manually if no binary is given
 * The printf offset bruteforcing range is insufficient

     * Overwrite `config.PRINTF_MAX` with an appropriate value.

 * The printf offset lies on an unaligned boundary. Some challenges are designed this way; workaround planned.

## Updates

pwnscripts is in development; if historical behaviour is broken it may be listed here

20-09

libc_db() can (must) now be initialised with either a filepath to a libc.so.6 `binary`, or with an identifier `id`. 

This breaks the original behaviour of allowing e.g. `libc_db('/path/to/libc-database', '<identifier>')`

20-08.1

NEW: printf() functions are now kept under the `pwnscripts.fsb` module. Older prototypes for find_printf_* functions remain available for now.

Addition of a lot of docstrings, plus example binaries.

20-08

Added a lot of whitespace.

Added a wrapper object for libc-database: the `libc_db` object. This is mostly a reinvention of tools like `LibcSearcher`, although I have yet to see another project tack on `one_gadget` searching, which is a (hacky) feature added for `libc_db`.

Minor adjustments to *printf*. Logging is suppressed for offset bruteforcing; new feature to make a leak payload.

Extended readme.

20-06

Added module packaging stuff, so that `pip install -e .` works

You can now see a test example of this library in `test.py`.

Gradual updates expected as I continue to do pwn.
