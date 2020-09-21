from os import path
from subprocess import check_output
import pwnlib
class ELF(pwnlib.elf.elf.ELF):
	def ldd_libs(self):
		'''For whatever reason, ELF.libs appears to be ineffectual.
		'''
		ldd = check_output(['ldd', self.path]).decode()
		libpaths = pwnlib.util.misc.parse_ldd_output(ldd).keys()
		return list(map(path.basename, libpaths))
