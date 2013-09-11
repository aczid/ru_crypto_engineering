/*

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

*/

#include <string.h>
#include <stdio.h>

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

typedef union {
	unsigned char 		bytes[8];
	long long unsigned int 	value;
} block_t;

typedef struct {
	unsigned char 	 	bytes[10];
} key_t;

#define test_bit(x,n)	x[(sizeof(x)-1)-(n/CHAR_BIT)] &  (1<<(n%CHAR_BIT))
#define set_bit(x,n)	x[(sizeof(x)-1)-(n/CHAR_BIT)] |= (1<<(n%CHAR_BIT))

const unsigned char sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};
const unsigned char inverse_sbox[16] = {
	0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};
const unsigned char *active_sbox = NULL;

unsigned int round_counter;
key_t 	key;
block_t state;

void rotate_left_i(int i){
	key_t newkey;
	unsigned int bit;
	memset(newkey.bytes, 0x0, 10);
	for(bit = 0; bit < 80; bit++){
		if(test_bit(key.bytes,bit)){
			set_bit(newkey.bytes,(bit+i)%80);
		}
	}
	memcpy(key.bytes, newkey.bytes, 10);
}

void schedule_key(void){
	/* 3. [k38k37k36k35k34] ^= round_counter - also stolen from Zhu/Gong */
	key.bytes[5] ^= round_counter << 2;

	/* 1. [k79k78..k1k0] = [k18k17..k20k19] */
	rotate_left_i(61);
	
	/* 2. [k79k78k77k76] = S[k79k78k77k76] */
	key.bytes[0] = (sbox[key.bytes[0] >> 4] << 4) | (key.bytes[0] & 0xf);
}

void addRoundKey(void){
	block_t roundkey;
	memcpy(roundkey.bytes, key.bytes, 8);
	state.value ^= roundkey.value;
}

void sBoxLayer(void){
	unsigned int i;
	for(i = 0; i < 8; i++){
		state.bytes[i] = (active_sbox[state.bytes[i] >> 4] << 4) | active_sbox[(state.bytes[i] & 0xf)];
	}
}

void pLayer(void){
	block_t newstate;
	unsigned int bit;
	newstate.value = 0;
	for(bit = 0; bit < 64; bit++){
		if(test_bit(state.bytes,bit)){
			set_bit(newstate.bytes,((16 * (bit % 4)) + (bit / 4)));
		}
	}
	state.value = newstate.value;
}

void setup(unsigned char *statebytes, unsigned char *keybytes){
	active_sbox = sbox;
	memcpy(state.bytes, statebytes, 8);
	memcpy(key.bytes, keybytes, 10);
}

void encrypt(unsigned char *statebytes, unsigned char *keybytes){
	setup(statebytes, keybytes);
	for(round_counter = 1; round_counter < 32; round_counter++){
		addRoundKey();
		sBoxLayer();
		pLayer();
		schedule_key();
	}
	addRoundKey();
	memcpy(statebytes, state.bytes, 8);
}

void decrypt(unsigned char *statebytes, unsigned char *keybytes){
	setup(statebytes, keybytes);
	for(round_counter = 1; round_counter < 32; round_counter++){
		schedule_key();
	}
	active_sbox = inverse_sbox;
	for(round_counter = 31; round_counter > 0; round_counter--){
		addRoundKey();
		pLayer();
		pLayer();
		sBoxLayer();

	inverse_schedule_key:
		key.bytes[0] = (inverse_sbox[key.bytes[0] >> 4] << 4) | (key.bytes[0] & 0xf);
		rotate_left_i(19);
		key.bytes[5] ^= round_counter << 2;
	}
	addRoundKey();
	memcpy(statebytes, state.bytes, 8);
}

void print_block(block_t block){
	printf("%02x%02x%02x%02x %02x%02x%02x%02x\n",
		block.bytes[0], block.bytes[1], block.bytes[2], block.bytes[3],
		block.bytes[4], block.bytes[5], block.bytes[6], block.bytes[7]
	);
}

void print_key(key_t key){
	printf("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x\n",
		key.bytes[0], key.bytes[1], key.bytes[2], key.bytes[3],
		key.bytes[4], key.bytes[5], key.bytes[6], key.bytes[7],
		key.bytes[8], key.bytes[9]
	);
}

void test(int keyval, int input){
	block_t test_state;
	key_t   test_key;
	memset(test_key.bytes, keyval, 10);
	test_state.value = input;

	printf("Key:        ");
	print_key(test_key);
	printf("Plaintext:  ");
	print_block(test_state);

	encrypt(test_state.bytes, test_key.bytes);

	printf("Ciphertext: ");
	print_block(test_state);

	decrypt(test_state.bytes, test_key.bytes);

	printf("Plaintext:  ");
	print_block(test_state);
	printf("\n");
}

int main(int argc, char* argv[]){
	test(0,0);
	test(-1,0);
	test(0,-1);
	test(-1,-1);

	return 0;
}


