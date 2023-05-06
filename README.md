mt-crypt - minimal stream cipher based on a (thought to be) cryptographically-
secure transformation of the Mersenne Twister PRNG

NOTE: I no longer host (new) projects on Github, preferring self-hosted solutions and
to avoid Github Copilot doing unauthorized scans of project code.
See https://gogs.blitter.com/RLabs/mt-crypt to learn more about this project and
to obtain the source code.

This package uses Geoff Kuenning's 'mtwist' MT implementation
[http://www.cs.hmc.edu/~geoff/mtwist.html] and
the BSD-licensed freestanding SHA code authored by Aaron Gifford, v1.0.1
[http://www.aarongifford.com/computers/sha.html]
and assumes prior to building that these have been extracted into
subdirectories:

```---
+
|
+-mtwist-1.4/
|
+-sha2-1.0.1/
|
+-mt-crypt/
```

Archives of mtwist-1.5 and sha2-1.0.1 are included along with this
distribution for completeness' sake; please refer to their respective
licenses.

To build, from mt-crypt/ just run 'make'. The makefile will attempt to build
'mtc.c', placing the executable in the same directory as 'Makefile'.

Build tested on cygwin under Windows 7 (32-bit), Mac OSX 10.6.x (x86_64) and
Linux.


Security
--------
The randomness of the resulting encrypted stream passes the 'randstdev'
randomness test tool

[http://sourceforge.net/projects/randstdev]

... when encrypting a test text file of 'War and Peace' as supplied
from archive.org and included in this distribution:

$ ./mtc <wrnpc11.txt >wrnpc11.txt.mtc

user@host ~/enc-prgs/mt-crypt
$ randstdev/programs/randstdev.exe <wrnpc11.txt
FAIL Average = 0.000000 +- 0.000000

user@host ~/enc-prgs/mt-crypt
$ randstdev/programs/randstdev.exe <wrnpc11.txt.mtc
PASS Average = 256.019155 +- 2.213782

Attacks
-------
Attack analyses have been performed on cryptMT and one should consider the
following:
[http://cr.yp.to/streamciphers/cryptmt/080.pdf]

This paper posits a 'distinguisher', which lets one possibly detect the use
of the MT PRNG as the basis for cryptoMT enciphered streams; but it is not
a key recovery attack as of yet.

Usage
-----
$ mtc {key} <plaintext >ciphertext

** NOTE this program will use a DEFAULT KEY (see mtc.c) if none is supplied.
