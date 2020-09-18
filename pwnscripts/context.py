'''A redefinition of pwntools' `context` to add on
some additional context attributes.'''
from os import path
from pwnlib import context
from pwnlib.log import getLogger
# IMPORTANT: pwnscripts must not be a relative import to prevent circular importing
import pwnscripts
log = getLogger('pwnlib.exploit')

class ContextType(context.ContextType):
	'''This is the extended class that inherits from
	pwnlib.context.ContextType. You can use it to spawn a
	_new_ context, but a new `ContextType()` will not affect
	pwnlib's original internal `pwnlib.context.context`,
	and consequently will not provide expected behaviour.

	Basically, don't init this object unless you know what you're doing.
	'''
	# Waiting for python3.9's dict unions here...
	defaults = {**context.ContextType.defaults,
				**{'libc_database': None, 'libc': None}}
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

_pwntools_context = context.context
_pwnscripts_context = ContextType()
_pwnscripts_LOCALS = ['libc_database', 'libc']
class ContextWrapper(ContextType):
	'''Wrapper over pwnlib.context.context so that modifications to
	pwnscripts.context.context will propagate correctly to the rest of pwnlib
	
	This wrapper is highly prone to unexpected behaviour. If you're reading this
	and you have a better programmatic suggestion, please raise an Issue/PullRequest!
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
