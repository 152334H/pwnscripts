# pwnscripts
Very simple script(s) to hasten binary exploit creation. To use, replace `from pwn import *` with `from pwnscripts import *`, e.g.

```python
from pwnscripts import *
context.binary = './my_challenge'
...
```

You might want to look at some of the examples in `test_all.py`.

It's messy and it works. Current features:
  * `find_printf_offset_*`: helper functions to bruteforce wanted printf offsets. Important ones:
    1. _buffer: find the offset to whatever's manipulating the input format string. A common example:
    2. _libc/_PIE: find a libc/PIE address with a specific offset
    
  * `libc_db`: a basic class for dealing with the libc-database project
    ```python
    db = libc_db('/path/to/libc-database', '<libc_id>') # e.g. libc6_2.27-3ubuntu1.2_amd64
    one_gadget = db.select_gadget() # Console will prompt for a selection. Behaviour may change.
    ... <insert exploit code to leak libc address here> ...
    # Let's say the libc address of `puts` was leaked as `libc_puts`
    libc_base = db.calc_base('puts', libc_puts)
    ```
  * `extract_(all|first)_hex`: simple wrapper for a hex value regex

## I tried using it; it doesn't work!

File in an [issue](https://github.com/152334H/pwnscripts/issues), if you can. With a userbase of 1, it's hard to guess what might go wrong, but potentially:
 * The software is broken
 * Python is outdated
 * The challenge is neither i386 or amd64; other architectures aren't implemented (yet).
 * The challenge is amd64, but `context.arch` wasn't set to `amd64`

     * Set `context.binary` appropriately, or set `context.arch` manually if no binary is given
 * The printf offset bruteforcing range is insufficient

     * Overwrite `PWNSCRIPT_PRINTF_MAX` with an appropriate value.

 * The printf offset lies on an unaligned boundary. Some challenges are designed this way; workaround planned.

## Updates

20-08

Added a lot of whitespace.

Added a wrapper object for libc-database: the `libc_db` object. This is mostly a reinvention of tools like `LibcSearcher`, although I have yet to see another project tack on `one_gadget` searching, which is a (hacky) feature added for `libc_db`.

Minor adjustments to *printf*. Logging is suppressed for offset bruteforcing; new feature to make a leak payload.

Extended readme.

20-06

Added module packaging stuff, so that `pip install -e .` works

You can now see a test example of this library in `test.py`.

Gradual updates expected as I continue to do pwn.
