#### v0.5.1dev - fsb.find_offset improvements
##### TODO
* Find some way to do automated testing on the cache system

##### Changes
###### New
 * `fsb.find_offset.<>()` will store a **cache** of leaked printf values.
   * Use `fsb.find_offset.flush_cache()` if anything goes wrong.
   * `README.md` has been updated appropriately.
 * `libc.run_with()` now has an argument for process constructor overridding.

###### Internal changes
 * `__all__` has been added to most source files to prevent namespace leaking.
 * Version history has been shifted to its [own separate file](CHANGELOG.md)

### v0.5.0 - Breaking Behavior

##### Changes
 * `string_checks` has been refactored:
   * `string_checks` itself is now named `util`
   * `is_X_address` functions have been renamed to `is_addr.X`
   * `extract_*` functions have been renamed to `unpack_*`
 * `libc_db()` from v0.1 is now fully removed from pwnscripts.
 * bugfixes for fsb.leak module

### v0.4.0 - ROP Update

##### Changes
###### New
 * `ROP.pop` && `ROP.system_call` overhaul
   * Use `ROP.pop.<reg>(value)` to pop a single register ASAP
   * `ROP.system_call.<func>(args)` is a similar shortcut
   * `ROP.system_call(id, ...)` will now accept a `str` for `id` (where `id` is the name of the syscall)
   * These changes mean that `help()` is essentially broken for these functions. In lieu of that, more docstrings!
   * Added a test for these changes
###### Internal changes
 * Some of the TODOs have been extended with short outlines

#### v0.3.1 - Documentation
##### Changes
 * very minor README.md edit.
 * hotfix for versioning

### v0.3.0 - libc update
##### Changes
###### New
 * Use `context.libc.run_with()` to run an `ELF()` with a specific libc version.
   * This is reliant on `ld-linux.so`; no more `LD_PRELOAD` segfaults!
   * `context.binary` is aware of `context.libc`, and will automagically use `.run_with()` where possible.
   * Added `context.libc.dir()` to get the `/path/to/libc-database/libs/libc.id/`.
   * Tests have been added for all of these things
 * `ELF` now has an `.ldd_libs()` method to get a list of libs used by a binary on wsl.
 * `rop.system_call()` can now search for `'syscall; ret'` instructions.
   * This is dependent on pwntools-dev

#### v0.2.1 - libc Hotfix
##### Changes
 * `libc.select_gadget()` will return with the correct `libc.address` adjusted value
 * hotfix for versioning

#### v0.2.0 - libc-database update
##### Changes
###### New
 * `pwnlib.context.context` is now extended for pwnscripts: `context.libc` and `context.libc_database` have been added as extensions.
 * `pwnscripts.libcdb_query` has undergone a revamp:
     * Two new classes have been created: `libc_database()` and `libc()`.
     * `libc()` is the replacement for `libc_db()`, and inherits from `pwnlib.elf.elf.ELF` to simplify libc offset calculation.
     * `libc_database()` is a class to represent an existing installation of the [`libc-database`](https://github.com/niklasb/libc-database)
     * More error catching
   
   The older `libc_db()` class (and the associated `libc_find()`) will remain as deprecated features for the time being.

###### Internal changes
 * Internal code: removal of `attrib_set_to()` & replacement with `context.local` internally
 * Tests & examples have been pruned to ensure that neither file has copied examples from the other.
 * Lots and lots of documentation + tests

#### v0.1.0 - Initial release
##### Changes
pwnscripts is out of pre-alpha, and will follow [Semantic Versioning](https://semver.org/) where possible.

---

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
