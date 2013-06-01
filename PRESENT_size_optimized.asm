; PRESENT cipher for AVR devices

; AUTHORS
; implemented by Aram Verstegen
; in collaboration with Kostas Papagiannopoulos
; based on work by:
;    Andrey Bogdanov et al (PRESENT authors)
;    Bo Zhu and Zheng Gong (efficient C version)
;    Thomas Eisenbarth     (Existing AVR implementation)

; INSTITUTE
; developed at Radboud Universiteit Nijmegen
; for the Cryptography Engineering course, 2012-2013
; part of the Kerckhoffs Institute master's program

; SPECIFICATIONS
; Size optimized version 2 - May 2013
; Code size (total):           290 bytes + 16 bytes for both packed s-boxes
; RAM words:                    18
; Cycle count (encryption):  90407
; Cycle count (decryption): 109968

; USE
; Point X at 8 input bytes followed by 10 key bytes and call encrypt or decrypt
; After having called encrypt or decrypt X will point to the start of the input

; Comment out either to omit
#define ENCRYPTION ; (can save 26 bytes by omitting)
#define DECRYPTION ; (can save 64 bytes by omitting)

#ifdef DECRYPTION
#define PACKED_SBOXES ; Use packed s-boxes (which need to be unpacked)
                      ; This saves 2 bytes
#endif

#ifdef PACKED_SBOXES
#define QUANTIZE_TIMING ; Avoid timing attacks when unpacking s-box values
#endif

;#define RELOCATABLE_SBOXES ; This makes s-boxes relocatable in flash
                            ; otherwise they are mapped at 0x100 and 0x200

; Number of rounds
.equ ROUNDS = 31

; Key registers (the first 8 of these hold the current round key)
.def KEY0 = r0
.def KEY1 = r1
.def KEY2 = r2
.def KEY3 = r3
.def KEY4 = r4
.def KEY5 = r5
.def KEY6 = r6
.def KEY7 = r7
.def KEY8 = r8
.def KEY9 = r9

; State (these hold the input on which the round key and s-box layer are applied)
.def STATE0 = r10
.def STATE1 = r11
.def STATE2 = r12
.def STATE3 = r13

; Output registers (these hold p-layer output to be saved to SRAM)
.def OUTPUT0 = r14
.def OUTPUT1 = r15
.def OUTPUT2 = r16
.def OUTPUT3 = r17

; Never used but needed for its 0 value to add carry bits with adc
.def ZERO = r18

; Register for s-box output
.def SBOX_OUTPUT = r19

; The round counter
.def ROUND_COUNTER = r20

; Shared register
; the index of the current round key byte being applied to the state in SRAM
.def KEY_INDEX = r21
; the index of the current s-box input
.def SBOX_INDEX = r21

; Low-byte offset to s-box in flash
.def SBOX_DISPLACEMENT = r22

; Register we can use for immediate values
.def ITEMP = r23

; registers r24..r25 are unused
; registers r26..r31 are X, Y and Z

; the Z register is used to point to these s-box tables
#ifdef PACKED_SBOXES
  #ifndef RELOCATABLE_SBOXES
.org 256
  #endif
SBOX:   .db 0xc5,0x6b,0x90,0xad,0x3e,0xf8,0x47,0x12
  #ifdef DECRYPTION
    #ifndef RELOCATABLE_SBOXES
.org 512
    #endif
INVSBOX:.db 0x5e,0xf8,0xc1,0x2d,0xb4,0x63,0x07,0x9a
  #endif
#else
  #ifndef RELOCATABLE_SBOXES
.org 256
  #endif
SBOX:   .db 0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2
  #ifdef DECRYPTION
    #ifndef RELOCATABLE_SBOXES
.org 512
    #endif
INVSBOX:.db 0x5,0xe,0xf,0x8,0xc,0x1,0x2,0xd,0xb,0x4,0x6,0x3,0x0,0x7,0x9,0xa
  #endif
#endif

; key scheduling
.macro schedule_key_macro
	; increment round counter
	inc ROUND_COUNTER
	; 1: rotate key register left by 61 positions
	ldi ITEMP, 6
	rcall rotate_left_i
	; 3: xor key bits with round counter
	; (as the 2 bytes align while rotating the key register)
	eor KEY4, ROUND_COUNTER
	; continue rotation
	ldi ITEMP, 55
	rcall rotate_left_i
	; 2: s-box high nibble of key
	mov ITEMP, KEY0
	rcall sBoxHighNibble
	mov KEY0, ITEMP
	; check if we are at ROUNDS for caller's loop
	cpi ROUND_COUNTER, ROUNDS
.endmacro

#if defined(ENCRYPTION) && defined(DECRYPTION)
schedule_key:
	schedule_key_macro
	ret
#endif

; apply last computed round key to the full 8-byte state in SRAM
addRoundKey:
	ldi KEY_INDEX, 8
addRoundKey_byte:
	; apply round key
	ld STATE0, X
	eor STATE0, KEY0
	st X+, STATE0
	; rotate key register to next byte
	ldi ITEMP, 8
	rcall rotate_left_i
	; loop over 8 bytes
	dec KEY_INDEX
	brne addRoundKey_byte

	; point at the start of the block
	subi XL, 8
	; rotate key register to align with the start of the block
	ldi ITEMP, 16
	; fall through

; rotate the 80-bit key register left by the number in ITEMP
rotate_left_i:
	lsl KEY9
	rol KEY8
	rol KEY7
	rol KEY6
	rol KEY5
	rol KEY4
	rol KEY3
	rol KEY2
	rol KEY1
	rol KEY0
	adc KEY9, ZERO
	dec ITEMP
	brne rotate_left_i
	ret

; sBoxByte
; applying the s-box nibble-wise allows us to reuse the second half of the
; procedure as its own procedure when key scheduling
; reads from and writes to ITEMP
; uses T (transfer) flag to re-do this block twice
sBoxHighNibble:
	clt                       ; clear T flag
	swap ITEMP                ; swap nibbles
	rjmp sBoxLowNibble        ; do the low nibble
sBoxByte:
	set                       ; set T flag
sBoxLowNibble:
	; input (low nibble)
	mov ZL, ITEMP             ; load s-box input
	cbr ZL, 0xf0              ; clear high nibble in s-box input
#ifdef RELOCATABLE_SBOXES
	add ZL, SBOX_DISPLACEMENT ; displacement for s-box pointer
#endif
#ifdef PACKED_SBOXES
	asr ZL                    ; halve input, take carry
#endif

	; output (low nibble)
	lpm SBOX_OUTPUT, Z        ; get s-box output

#ifdef PACKED_SBOXES
	brcs odd_unpack           ; 2 cycles if true, 1 if false
even_unpack:
	swap SBOX_OUTPUT          ; 1 cycle
  #ifdef QUANTIZE_TIMING
	rjmp unpack               ; 2 cycles
  #endif
odd_unpack:                       ; avoid timing attacks
  #ifdef QUANTIZE_TIMING
	nop                       ; 1 cycle
	nop
  #endif
; 4 cycles total
unpack:
	cbr SBOX_OUTPUT, 0xf0
#endif

	cbr ITEMP, 0xf            ; clear low nibble in output
	or ITEMP, SBOX_OUTPUT     ; save low nibble to output
	brts sBoxHighNibble       ; do high nibble (if T flag set)
	swap ITEMP                ; swap nibbles back
	ret

.macro sBoxLayer_macro
; apply loaded s-box to the full 8-byte state in SRAM
	ldi SBOX_INDEX, 8
sBoxLayer_byte:
	; apply s-box
	ld ITEMP, X
	rcall sBoxByte
	st X+, ITEMP
	; loop over 8 bytes
	dec SBOX_INDEX
	brne sBoxLayer_byte

	; point at the start of the block
	subi XL, 8
.endmacro

#if defined(ENCRYPTION) && defined(DECRYPTION)
sBoxLayer:
	sBoxLayer_macro
	ret
#endif

; apply half the p-layer from state to output registers
pLayerHalf:
	mov ITEMP, STATE3
	rcall pLayerByte
	mov ITEMP, STATE2
	rcall pLayerByte
	mov ITEMP, STATE1
	rcall pLayerByte
	mov ITEMP, STATE0
	; fall through

; pLayerByte
; approach stolen from KULeuven implementation

; splices 1 input byte over 4 output bytes, which will then each hold 2 bits
; following a 4-bit period in the input

; reads from ITEMP and saves to output registers
; after 4 calls from different input registers we will have collected 4
; completed output bytes following this 4-bit period

; uses T (transfer) flag to re-do this block twice
pLayerByte:
	set                            ; set T flag
continue_pLayerByte:
	ror ITEMP                      ; move bit into carry
	ror OUTPUT0                    ; move bit into output register
	ror ITEMP                      ; etc
	ror OUTPUT1
	ror ITEMP
	ror OUTPUT2
	ror ITEMP
	ror OUTPUT3
	brts setup_continue_pLayerByte ; redo this block? (if T flag set)
	ret
setup_continue_pLayerByte:
	clt                            ; clear T flag
	rjmp continue_pLayerByte       ; do the second part

; load 4 input bytes from SRAM into state registers
consecutive_input:
	ld STATE0, X+
	ld STATE1, X+
	ld STATE2, X+
	ld STATE3, X+
	ret

; apply the p-layer to the full 8-byte state in SRAM
pLayer:
	; get high/left 4 bytes as p-layer input 
	rcall consecutive_input

	; apply p-layer half
	rcall pLayerHalf

	; get low/right 4 bytes as next p-layer input
	rcall consecutive_input

	; save p-layer output to SRAM
	dec XL
	rcall interleaved_output
	adiw XL, 9

	; apply other p-layer half
	rcall pLayerHalf

	; save p-layer output to SRAM
	; fall through

; save 4 bytes from output registers into SRAM from back to front
; leaves 1 byte untouched in between each saved byte
interleaved_output:
	st -X, OUTPUT0
	dec XL
	st -X, OUTPUT1
	dec XL
	st -X, OUTPUT2
	dec XL
	st -X, OUTPUT3
	dec XL
	ret

; prepare for encryption or decryption
.macro setup_macro
	; clear zero register
	clr ZERO
	; clear round counter
	clr ROUND_COUNTER
	; initialize s-box
	ldi ZH, high(SBOX<<1)
#ifdef RELOCATABLE_SBOXES
  #ifdef PACKED_SBOXES
	ldi SBOX_DISPLACEMENT, low(SBOX<<2)
  #else
	ldi SBOX_DISPLACEMENT, low(SBOX<<1)
  #endif
#endif
	; point at the key bytes
	adiw XL, 8
	; load key from SRAM
	ld KEY0, X+
	ld KEY1, X+
	ld KEY2, X+
	ld KEY3, X+
	ld KEY4, X+
	ld KEY5, X+
	ld KEY6, X+
	ld KEY7, X+
	ld KEY8, X+
	ld KEY9, X+
	; point at the start of the input
	subi XL, 18
.endmacro

#if defined(ENCRYPTION) && defined(DECRYPTION)
setup:
	setup_macro
	ret
#endif

#ifdef ENCRYPTION

; encryption function: point X at 8 plaintext input bytes followed by 10 key input bytes
encrypt:
	#ifndef DECRYPTION
	setup_macro
	#else
	rcall setup
	#endif
	encrypt_update:
		; apply round key
		rcall addRoundKey

		; apply s-box layer
		#ifndef DECRYPTION
		sBoxLayer_macro
		#else
		rcall sBoxLayer
		#endif

		; apply p-layer
		rcall pLayer

		; schedule next key
		#ifndef DECRYPTION
		schedule_key_macro
		#else
		rcall schedule_key
		#endif

		; loop for ROUNDS
		brne encrypt_update
	; add final round key
	rjmp addRoundKey
#endif

#ifdef DECRYPTION

; decryption function: point X at 8 ciphertext input bytes followed by 10 key input bytes
decrypt:
	#ifndef ENCRYPTION
	setup_macro
	#else
	rcall setup
	#endif

	; schedule key for last round
	schedule_last_key:
		#ifndef ENCRYPTION
		schedule_key_macro
		#else
		rcall schedule_key
		#endif
		brne schedule_last_key

	; initialize inv s-box
	ldi ZH, high(INVSBOX<<1)
#ifdef RELOCATABLE_SBOXES
  #ifdef PACKED_SBOXES
	ldi SBOX_DISPLACEMENT, low(INVSBOX<<2)
  #else
	ldi SBOX_DISPLACEMENT, low(INVSBOX<<1)
  #endif
#endif

	; start round
	decrypt_update:
		; apply round key
		rcall addRoundKey

		; invert p-layer
		rcall pLayer
		rcall pLayer

		; apply inverse s-box layer
		#ifndef ENCRYPTION
		sBoxLayer_macro
		#else
		rcall sBoxLayer
		#endif

		; schedule previous key
		inv_schedule_key:
			; 2: inv s-box high nibble of key
			mov ITEMP, KEY0
			rcall sBoxHighNibble
			mov KEY0, ITEMP
			; 1: rotate key register left by 19 positions
			ldi ITEMP, 17
			rcall rotate_left_i
			; 3: xor key bits with round counter
			; (as the 2 bytes align while rotating the key register)
			eor KEY5, ROUND_COUNTER
			; continue rotation
			ldi ITEMP, 2
			rcall rotate_left_i
			; decrement round counter
			dec ROUND_COUNTER

		; loop for ROUNDS
		brne decrypt_update
	; apply final round key
	rjmp addRoundKey
#endif
