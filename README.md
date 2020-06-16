# pwnscripts
Very simple script(s) to hasten binary exploit creation. To use, replace `from pwn import *` with `from pwnscripts import *`.

It's messy and it works. Current features:
  * `find_printf_offset_*`: helper functions to bruteforce wanted printf offsets
  * `extract_(all|first)_hex`: simple wrapper for a hex value regex

Gradual updates expected as I continue to do pwn.
