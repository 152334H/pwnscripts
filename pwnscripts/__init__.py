'''A simple QoL module to make doing repetitive pwn easier'''
from pwn import *
from pwnscripts.context import context	# Keep this at top-level
from pwnscripts.elf import *
from pwnscripts.util import *
from pwnscripts.libcdb_query import *
from pwnscripts.uncommon import *
from pwnscripts.rop import *
import pwnscripts.fsb as fsb

def pwnscripts_config(section):
    for key, value in section.items():
        if key == 'libc_database': context.libc_database = value
        else: log.warn("Unknown configuration option %r in section %r" % (key, 'context'))
from pwnlib.config import register_config
register_config('pwnscripts', pwnscripts_config)
pwnlib.config.initialize()
