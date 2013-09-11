RU Cryptography Engineering
===========================
This is the code repository for our assignments in
[Cryptography Engineering](http://rucryptoengineering.wordpress.com) at the 
[Radboud Universiteit in Nijmegen](http://www.ru.nl/) as part of the 
[Kerckhoffs Institute](http://www.kerckhoffs-institute.org/) master's program in
computer security.

PRESENT
=======
We implemented the
[PRESENT cipher](http://en.wikipedia.org/wiki/PRESENT_%28cipher%29)
in C and AVR assembly based on
[the original paper](http://homes.esat.kuleuven.be/~abogdano/papers/present_ches07.pdf),
[the C version by Zhu/Gong](http://cis.sjtu.edu.cn/index.php/Software_Implementation_of_Block_Cipher_PRESENT_for_8-Bit_Platforms)
and
[the Louvain AVR implementation](http://perso.uclouvain.be/fstandae/lightweight_ciphers/).
We drafted two AVR assembly implementations, one for maximal speed and one for
minimal size.
The C version was drafted to better understand/illustrate/analyze the cipher's
behaviour before we began.

This AVR assembly version was optimized for small code size at the expense of
speed on the [Atmel ATtiny45 microcontroller](
http://www.atmel.com/devices/attiny45.aspx).
The speed-optimized AVR assembly version of the algorithm can be found at
[my co-author's github browsable repository](
https://github.com/kostaspap88/PRESENT_speed_implementation/).

The current version requires 256 code bytes for the encryption and decryption
routines, and 16 bytes for s-box tables at addresses 0x100 and 0x200.

* Size optimized version 2 - May 2013
* Code size (total):           256 bytes + 16 bytes for both packed s-boxes
* RAM words:                    18
* Cycle count (encryption): 190045
* Cycle count (decryption): 253380

Settings
========
For specific applications that require only encryption or decryption, the code
size can be further reduced.
The code for either procedure can be easily omitted by commenting out the
**ENCRYPTION** or **DECRYPTION** define statement.

Support for 128-bit keys can be enabled by uncommenting the **PRESENT_128**
define statement at no extra cost.

Much (about 4x) better performance can be enabled by uncommenting the
**FAST_ROTATE** define statement at a cost of 4/16 extra bytes (depending
on key size).

At a cost of 6 extra bytes the s-box tables can be located at addresses not
aligned to 256 bytes when the **RELOCATABLE_SBOXES** define statement is
uncommented, provided the tables do not span a 256-byte address boundary.
This allows the encryption and decryption code + packed s-box tables to fit in
278 consecutive bytes of flash.

To get a tiny bit more performance at the expense of 2 bytes the
**PACKED_SBOXES** define statement can be commented out to use 16-byte s-box
tables and omit the 14-byte unpacking code.
NB: The timing quantization of unpacking was tested on our ATtiny45 simulator,
for different devices it's probably best to disable the packed s-boxes entirely.

Zeroisation of the key in SRAM can be enabled by uncommenting the **ZERO_KEY**
define statement at a cost of 2 extra bytes.

Authors
=======
 * Aram Verstegen, aram.verstegen@gmail.com
 * Kostas Papagiannopoulos, kostaspap88@gmail.com

ASCII art
=========
To give a visual representation of the compactness of the implementation, and
as a geeky sort of art inspired by the [RSA dolphin](
http://e-privacy.winstonsmith.info/2007/2005/2002/munitions/documents/rsafin),
here is the compiled AVR code (configured with relocatable s-boxes) in ASCII
hexadecimal as a banner.
(Created with [this script](https://gist.github.com/aczid/5703046), 
then manually adjusted kerning.)

    s-boxes                                     decrypt (start+16)
    |                                           |
    C56B90AD   3EF84712   5EF8C12    DB4630  79A57D0  3AD0    F1F  7F0E070E1
    41D05DD05  CD047D080  2D16D00   82E81E1  06D0542  682E0   03D  04A9591F7
    33C0CAE08  894CA9598  81991F9   883CD13  FACF9D1  E8A95   A9F  7089504D0
    829   502  D08   295  089       5E8      2FE      F70E70  FE5     955
    491  10F0  529   502  C00       0000     000      5F7080  7F8     52B
    089587950  795879517  9587952   795879   5379508  9543958 6E0     D5D
    F442687E3  D2DF802DD  DDF082E   4F31089  5CC278C  916 991 862     78D
    93C830D1   F7A85008   9568E08     C91CD  DF8D936  A95 D9F7A85     008
    954        427 F0E0   70E          0189  6DD      27C  C278D9     189
    93C        A30 E1F7A  251      08   956  894      189  664E08     E91
    CAD        FC9  DF6A  95D9F73  F932F931  F930F93  16F   4E894     F3C
    F68        941   7966 4E08F91  8E93AA95  6A95D9F  71E   F4E89     419
    96F        6CF   0895D7DFC5DF  CDDFE0D   FB7DFD9  F7C    0CF0     000
                         |
                         encrypt (end-16)

To get a programmable rom, pipe this graphic (without offset annotations) into:

    tr -d ' \n' | perl -ne 's/([0-9a-f]{2})/print chr hex $1/gie' | bin2hex.py -

(I.e. strip newlines and spaces, decode ASCII hex to binary and convert to
programmable .hex format.)

To inspect the code:

    avr-objdump -mavr -D <hex file>

Or if you have [radare2](http://radare.org/) you can pipe the banner directly
into:

    tr -d ' \n' | rasm2 -aavr -d -f -

Disclaimer
==========
This is experimental software, created for research purposes, specifically
optimized for the **ATtiny45** device.

We have observed constant-time behaviour in our simulations, but we make no
claims about the security of the implementation against further cryptanalysis.
While we offer the option to zeroise the key in SRAM while reading, this is not
meant as any guarantee against data remanence.
We merely assert our implementations are correct with respect to the references
used.

We **DO NOT** recommend this software to be used in development of secure
applications until further notice.
In fact, **we hereby invite anybody to break our implementations and/or suggest
improvements**.

License
=======

Copyright (c) 2013 Aram Verstegen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

