RU Cryptography Engineering
===========================
This is the code repository for our assignments in [Cryptography Engineering](http://rucryptoengineering.wordpress.com) at the [Radboud Universiteit in Nijmegen](http://www.ru.nl/) as part of the [Kerckhoffs Institute](http://kerckhoffs-institute.org/) master's program in computer security.

PRESENT
=======
We implemented the PRESENT cipher in C and AVR assembly based on the original paper, the C version by Zhu/Gong and the Leuven AVR implementation.

This AVR assembly version was optimized for small code size at the expense of speed.
The current version requires 280 code bytes for the encryption and decryption routines, and 16 bytes for s-box tables at addresses 0x100 and 0x200.

* Size optimized version 2 - May 2013
* Code size (total):           280 bytes + 16 bytes for both packed s-boxes
* RAM words:                    18
* Cycle count (encryption):  94344
* Cycle count (decryption): 116106

The speed-optimized version of the algorithm can be found at [my co-author's github browsable repository](https://github.com/kostaspap88/PRESENT_speed_implementation/).

Settings
========
For specific applications that require only encryption or decryption, the code size can be further reduced.
The code for either procedure can be easily omitted by commenting out the **ENCRYPTION** or **DECRYPTION** define statement.

At a cost of 6 extra bytes the s-box tables can be located at addresses not aligned to 256 bytes when the **RELOCATABLE_SBOXES** define statement is uncommented, provided the tables do not span a 256-byte address boundary. This allows the encryption and decryption code + packed s-box tables to fit in 302 consecutive bytes of flash.

To get a tiny bit more performance at the expense of 2 bytes the **PACKED_SBOXES** define statement can be commented out to use 16-byte s-box tables and omit the 14-byte unpacking code.

Although it is unadvised, there is the option of not quantizing the timing of s-box application by commenting out the **QUANTIZE_TIMING** define statement to save 6 bytes.

Authors
=======
 * Aram Verstegen, aram.verstegen@gmail.com
 * Kostas Papagiannopoulos, kostaspap88@gmail.com

