# pwnscripts
Very simple script(s) to hasten binary exploit creation. To use, run
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

You might want to look at some of the examples in `test_all.py`.

## Features

Current features:
  * `fsb`, which can be split further into
    * `.find_offset`: helper functions to bruteforce wanted printf offsets.

      If you've ever found yourself spamming `%n$llx` into a terminal: this module will automate away all that. Take a look at the [example code](test_all.py) to see how.

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

  * `libc_db`: a basic class for dealing with the libc-database project. **Unlike LibcSearcher** (for now), this class has a wrapper to help with finding one_gadgets as well.
    ```python
    db = libc_db('/path/to/libc-database', binary='/path/to/libc.so.6') # e.g. libc6_2.27-3ubuntu1.2_amd64
    one_gadget = db.select_gadget() # Console will prompt for a selection. Behaviour may change.
    ... <insert exploit code to leak libc address here> ...
    # Let's say the libc address of `puts` was leaked as `libc_puts`
    libc_base = db.calc_base('puts', libc_puts)
    ```
  * `ROP`: an extension of `pwnlib.rop.rop.ROP`. Core feature is to simplify ROP building outside of SIGROP:
    ```python
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
    ```
  * other unlisted features in development

Proper examples for `pwnscripts` are available in `examples/` and `test_all.py`.
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

NEW: `pwntools`' `ROP` class has been extended with new features.

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
