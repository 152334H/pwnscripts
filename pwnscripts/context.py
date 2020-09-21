'''A redefinition of pwntools' `context` to add on
some additional context attributes.'''
from os import path
from pwnlib import context
from pwnlib.log import getLogger
from pwnlib.elf.elf import ELF
# IMPORTANT: pwnscripts must not be a relative import to prevent circular importing
import pwnscripts
log = getLogger('pwnlib.exploit')

_pwntools_context = context.context
_pwnscripts_LOCALS = ['libc_database', 'libc', 'binary', 'clear']

class ContextType(context.ContextType):
	'''This is the extended class that inherits from
	pwnlib.context.ContextType. You can use it to spawn a
	_new_ context, but a new `ContextType()` will not* affect
	pwnlib's original internal `pwnlib.context.context`,
	and consequently will not provide expected behaviour.

	Basically, don't init this object unless you know what you're doing.

	*Unfortunately, assigning to .binary *will* currently affect pwntools' context.
	This is planned to be fixed.
	'''
	# Waiting for python3.9's dict unions here...
	defaults = {**context.ContextType.defaults,
				**{'libc_database': None, 'libc': None, 'binary': None}}
	
	def clear(self, *a, **kw):
		'''overwritten pwnscripts method: clear pwnscripts context as well
		'''
		self._tls._current.clear()
		super().clear(*a, **kw)
	@context._validator
	def binary(self, binary):
		'''overwritten pwnscripts method: spawn context.binary with pwnscript's ELF()
		'''
		# Some parts of pwnlib make use of context.binary, so we need to write to _pwntools_context
		# This breaks the original design of ContextType, but no better solution has been concieved
		_pwntools_context.binary = binary
		if not isinstance(binary, ELF):	# This is pwnlib's ELF
			import pwnscripts.elf
			binary = pwnscripts.elf.ELF(binary)
		return binary

	@context._validator
	def libc_database(self, db_dir: str):
		'''
		>>> context.libc_database = 'libc-database'
		>>> context.libc_database
		<pwnscripts.libcdb_query.libc_database object at 0x7fffffffffff>
		'''
		return pwnscripts.libc_database(db_dir)
	
	@context._validator
	def libc(self, assigned:str):
		'''
		>>> context.libc_database = 'libc-database'
		>>> context.libc = 'examples/libc.so.6'
		[*] '/path/to/pwnscripts/libc-database/db/libc6_2.27-3ubuntu1_amd64.so'
		Arch:     amd64-64-little
		RELRO:    Partial RELRO
		Stack:    Canary found
		NX:       NX enabled
		PIE:      PIE enabled
		>>> context.libc
		libc('/path/to/pwnscripts/libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
		or 
		>>> context.libc = 'libc6_2.27-3ubuntu1_amd64'
		[*] libc=`'libc6_2.27-3ubuntu1_amd64'' is not a file; assuming a libc-database id was given!
		>>> context.libc
		libc('/path/to/pwnscripts/libc-database/db/libc6_2.27-3ubuntu1_amd64.so')
		'''
		if type(assigned) != str:	# assume a libc() object was given
			return assigned
		if path.isfile(assigned):	# assume binary
			return pwnscripts.libc(binary=assigned)
		# assume id
		log.info("libc=`%r' is not a file; assuming a libc-database id was given!" % assigned)
		return pwnscripts.libc(id=assigned)

_pwnscripts_context = ContextType()
class ContextWrapper(ContextType):
	'''Wrapper over pwnlib.context.context so that modifications to
	pwnscripts.context.context will propagate correctly to the rest of pwnlib
	
	This wrapper is highly prone to unexpected behaviour. If you're reading this
	and you have a better programmatic suggestion, please raise an Issue/PullRequest!

	An example of unexpected behaviour:
	>>> with context.local(log_level='info'): context.arch = 'arm'
	>>> context.arch == 'arm'
	False
	>>> with context.local(log_level='info'): context.binary = 'mybinary'
	>>> context.binary is None
	False
	In the first instance, context.arch is not preserved (*expected behaviour*)
	because it's assignment should be contained to the with-statement.
	In the second instance, context.binary *is preserved* because it is one of the
	overwritten methods in pwnscripts.
	'''
	def __setattr__(self, attr, value):
		if attr not in _pwnscripts_LOCALS:
			return setattr(_pwntools_context, attr, value)
		return setattr(_pwnscripts_context, attr, value)

	def __getattribute__(self, attr):
		if attr not in _pwnscripts_LOCALS:
			return getattr(_pwntools_context, attr)
		return getattr(_pwnscripts_context, attr)

context = ContextWrapper()
