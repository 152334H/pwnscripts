from os import path
from subprocess import check_output
import pwnlib

from pwnscripts.context import context
class ELF(pwnlib.elf.elf.ELF):
	def ldd_libs(self) -> list:
		'''ELF.libs fails on wsl. This function is here for that purpose.
		Returns: list of library basenames detected by ldd.
		'''
		ldd = check_output(['ldd', self.path]).decode()
		libpaths = pwnlib.util.misc.parse_ldd_output(ldd).keys()
		return list(map(path.basename, libpaths))

	def process(self, argv=[], *a, **kw) -> pwnlib.tubes.process.process:
		'''pwnscripts overridden .process() method
		If `context.libc` is set, process() will run
			context.libc.run_with(self, argv, *a, **kw)
		Otherwise, the original pwntools' ELF.process() is called.

		Returns:
			pwnlib.tubes.process.process() object
		'''
		if context.libc is None:
			return super().process(argv, *a, **kw)
		return context.libc.run_with(self, argv, *a, **kw)