RU Cryptography Engineering
===========================
This is the code repository for our assignments in Cryptography Engineering at the Radboud Universiteit in Nijmegen as part of the Kerckhoffs Institute master's program in computer security.
The website for the course is: http://rucryptoengineering.wordpress.com
The Kerckhoffs institute's website is: http://kerckhoffs-institute.org/

PRESENT
=======
We implemented the PRESENT cipher in C and AVR assembly based on the original paper, the C version by Zhu/Gong and the Leuven AVR implementation.

This AVR assembly version was optimized for small code size at the expense of speed.
The current version requires 402 code bytes for the encryption and decryption routines and 16 bytes for s-boxes at adresses 0x100 and 0x200.
For specific applications that require only encryption or decryption, the code size can be further reduced.
Which procedure is omitted can be easily controlled by commenting out the ENCRYPTION or DECRYPTION define statement.

* Code size (total):           402 bytes + 16 bytes for both packed s-boxes
* RAM words:                    18
* Cycle count (encryption):  95320
* Cycle count (decryption): 107286

The speed-optimized version of the algorithm can be found at my co-author's github browsable repository:
https://github.com/kostaspap88/PRESENT_speed_implementation/

Authors
=======
 * Aram Verstegen, aram.verstegen@gmail.com
 * Kostas Papagiannopoulos, kostaspap88@gmail.com		  

