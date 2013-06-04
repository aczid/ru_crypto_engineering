RU Cryptography Engineering
===========================
This is the code repository for our assignments in [Cryptography Engineering](http://rucryptoengineering.wordpress.com) at the [Radboud Universiteit in Nijmegen](http://www.ru.nl/) as part of the [Kerckhoffs Institute](http://kerckhoffs-institute.org/) master's program in computer security.

PRESENT
=======
We implemented the PRESENT cipher in C and AVR assembly based on the original paper, the C version by Zhu/Gong and the Leuven AVR implementation.

This AVR assembly version was optimized for small code size at the expense of speed.
The current version requires 264 code bytes for the encryption and decryption routines, and 16 bytes for s-box tables at addresses 0x100 and 0x200.

* Size optimized version 2 - May 2013
* Code size (total):           264 bytes + 16 bytes for both packed s-boxes
* RAM words:                    18
* Cycle count (encryption): 210445 (57274 for 2 extra instructions)
* Cycle count (decryption): 279916 (79036 for 2 extra instructions)

The speed-optimized version of the algorithm can be found at [my co-author's github browsable repository](https://github.com/kostaspap88/PRESENT_speed_implementation/).

Settings
========
For specific applications that require only encryption or decryption, the code size can be further reduced.
The code for either procedure can be easily omitted by commenting out the **ENCRYPTION** or **DECRYPTION** define statement.

Support for 128-bit keys can be enabled by uncommenting the **PRESENT_128** define statement at no extra cost.

Much (about 4x) better performance can be enabled by uncomment the **PERFORMANCE** define statement at a cost of 4/10 extra bytes (depending on key size).

At a cost of 6 extra bytes the s-box tables can be located at addresses not aligned to 256 bytes when the **RELOCATABLE_SBOXES** define statement is uncommented, provided the tables do not span a 256-byte address boundary. This allows the encryption and decryption code + packed s-box tables to fit in 286 consecutive bytes of flash.

To get a tiny bit more performance at the expense of 2 bytes the **PACKED_SBOXES** define statement can be commented out to use 16-byte s-box tables and omit the 14-byte unpacking code.

Although it is unadvised, there is the option of not quantizing the timing of s-box application by commenting out the **QUANTIZE_TIMING** define statement to save 6 bytes.

Authors
=======
 * Aram Verstegen, aram.verstegen@gmail.com
 * Kostas Papagiannopoulos, kostaspap88@gmail.com

Compiled AVR code in ascii-hex art
==================================

    C56B90AD   3EF84712   5EF8C12    DB4630   79ACAE0   8894    CA9  59881991F
    9883CD13F  ACF9D1E8A  95A9F70   89504D0   829502D   08295   089  5E82FEF70
    E59554911  0F0529502  C000000   0005F70   807F852   B0895   879  507958795
    179   587  952   795  879       537       950       895689  418     966   
    4E0  8E91  F2D   FF1  DF6       A95D      9F7       3F932F  931     F93   
    0F936EF06  894179664  E08F918   E93AA9    56A95D9   F70EF00 895     E89   
    41996F5CF  E894E6CF4  39586E0   BADF442   687E3B7   DF8 02D C2D     F08   
    2E4F3108   95CC278C   9169918     6278D   93C830D   1F7 A850089     568   
    E08        C91 B2DF   8D9          36A9   5D9       F7A  850089     544   
    27F        2E0 1896D  D27      CC   278   D91       899  3CA30E     1F7   
    A25        108  95F4  DFE2DFE  ADFB9DFD   4DFD9F7   DDC   FEDDF     D0D   
    FF1        F7F   4E0D 8DFB0DF  AFDFDEDF   802D92D   F08   2E81E     182   
    DF5        426   82E07FDF4A95  91F7CAC    F000000   000    0000     000

