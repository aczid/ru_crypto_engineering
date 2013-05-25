RU Cryptography Engineering
===========================
This is the code repository for our assignments in [Cryptography Engineering](http://rucryptoengineering.wordpress.com) at the [Radboud Universiteit in Nijmegen](http://www.ru.nl/) as part of the [Kerckhoffs Institute](http://kerckhoffs-institute.org/) master's program in computer security.

PRESENT
=======
We implemented the PRESENT cipher in C and AVR assembly based on the original paper, the C version by Zhu/Gong and the Leuven AVR implementation.

This AVR assembly version was optimized for small code size at the expense of speed.
The current version requires 378 code bytes for the encryption and decryption routines, and 16 bytes for s-box tables at addresses 0x100 and 0x200.
The s-box tables can be located at addresses not aligned to 256 bytes when the **RELOCATABLE_SBOXES** define is uncommented, provided the tables do not cross a 256-byte boundary. This allows the encryption and decryption code + packed s-box tables to fit in 400 consecutive bytes of flash.

For specific applications that require only encryption or decryption, the code size can be further reduced.
The code for either procedure can be easily omitted by commenting out the **ENCRYPTION** or **DECRYPTION** define statement.

* Code size (total):           378 bytes + 16 bytes for both packed s-boxes
* RAM words:                    18
* Cycle count (encryption):  94845
* Cycle count (decryption): 105447

The speed-optimized version of the algorithm can be found at [my co-author's github browsable repository](https://github.com/kostaspap88/PRESENT_speed_implementation/)

Authors
=======
 * Aram Verstegen, aram.verstegen@gmail.com
 * Kostas Papagiannopoulos, kostaspap88@gmail.com		  

