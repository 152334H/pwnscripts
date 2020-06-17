# pwnscripts
Very simple script(s) to hasten binary exploit creation. To use, replace `from pwn import *` with `from pwnscripts import *`.

It's messy and it works. Current features:
  * `find_printf_offset_*`: helper functions to bruteforce wanted printf offsets. Important ones:
    1. _buffer: find the offset to whatever's manipulating the input format string
    2. _libc/_PIE: find a libc/PIE address with a specific offset
  * `extract_(all|first)_hex`: simple wrapper for a hex value regex

## Updates

You can now see a test example of this library in `test.py`.

Gradual updates expected as I continue to do pwn.
