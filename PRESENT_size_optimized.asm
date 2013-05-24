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
; Code size (total):           378 bytes + 16 bytes for both packed s-boxes
; RAM words:                    18
; Cycle count (encryption):  94845
; Cycle count (decryption): 105447

; USE
; Point X at 8 input bytes followed by 10 key bytes and call encrypt or decrypt
; After having called encrypt or decrypt X will point to the end of the input

; Number of rounds
.equ ROUNDS = 32 ; PRESENT round counter is initialized to 1. This value means there are 31 rounds (+ 1 final round key)

; Comment out either to omit
#define ENCRYPTION
#define DECRYPTION

#ifdef DECRYPTION
#define PACKED_SBOXES ; Use packed s-boxes (which need to be unpacked) - this saves 2 bytes
#endif

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

; Output registers (these hold the last state to be saved to SRAM while the next state is read)
.def OUTPUT0 = r14
.def OUTPUT1 = r15
.def OUTPUT2 = r16
.def OUTPUT3 = r17

; Never used but needed for its 0 value to add carry bits with adc
.def ZERO = r18

; Shared register for s-box output and to count key register rotations
.def SBOX_OUTPUT = r19
.def ROTATION_COUNTER = r19

; The round counter
.def ROUND_COUNTER = r20

; Offset to the current key byte being applied to the state in SRAM
.def KEY_INDEX = r21

; Register we can use for immediate values
.def ITEMP = r22

; registers r23..r25 are unused
; registers r26..r31 are X, Y and Z

; the Z register is used to point to these s-box tables
#ifdef PACKED_SBOXES
.org 256
SBOX:   .db 0xc5,0x6b,0x90,0xad,0x3e,0xf8,0x47,0x12
  #ifdef DECRYPTION
.org 512
INVSBOX:.db 0x5e,0xf8,0xc1,0x2d,0xb4,0x63,0x07,0x9a
  #endif
#else
.org 256
SBOX:   .db 0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2
  #ifdef DECRYPTION
.org 512
INVSBOX:.db 0x5,0xe,0xf,0x8,0xc,0x1,0x2,0xd,0xb,0x4,0x6,0x3,0x0,0x7,0x9,0xa
  #endif
#endif


; -------------------------------------
;           PRESENT procedures
; -------------------------------------

; pLayerByte
; approach stolen from KULeuven implementation

; splices 1 input byte over 4 output bytes, which will then each hold 2 bits
; following a 4-bit period in the input

; reads from ITEMP and saves to output registers
; after 4 calls from different input registers we will have collected 4
; completed output bytes following this 4-bit period

; uses H (half-carry) flag to re-do this block twice
setup_continue_pLayerByte:
	clh                            ; clear H flag
	rjmp continue_pLayerByte       ; do the second part
ipLayerByte:
	seh                            ; set H flag
	rjmp continue_pLayerByte       ; do the second part
pLayerByte:
	seh                            ; set H flag
	ror ITEMP                      ; move bit into carry
	; fall through
continue_pLayerByte:
	ror OUTPUT0                    ; move bit into output register
	ror ITEMP                      ; etc
	ror OUTPUT1
	ror ITEMP
	ror OUTPUT2
	ror ITEMP
	ror OUTPUT3
	ror ITEMP
	brhs setup_continue_pLayerByte ; redo this block? (if H flag set)
	ret

; sBoxByte
; applying the s-box nibble-wise allows us to reuse the second half of the
; procedure as its own procedure when key scheduling
; reads from and writes to ITEMP
; uses H (half-carry) flag to re-do this block twice
sBoxHighNibble:
	clh                   ; clear H flag
	swap ITEMP            ; swap nibbles
	rjmp sBoxLowNibble    ; do the low nibble
sBoxByte:
	seh                   ; set H flag
	; fall through
sBoxLowNibble:
	; input (low nibble)
	mov ZL, ITEMP         ; load s-box input
	cbr ZL, 0xf0          ; clear high nibble in s-box input

	; output (low nibble)
#ifdef PACKED_SBOXES
	asr ZL                ; halve input, take carry
#endif
	lpm SBOX_OUTPUT, Z    ; get s-box output

#ifdef PACKED_SBOXES
	brcs odd_unpack       ; 2 cycles if true, 1 if false
even_unpack:
	swap SBOX_OUTPUT      ; 1 cycle
	rjmp unpack           ; 2 cycles
odd_unpack:                   ; avoid timing attacks
	nop                   ; 1 cycle
	nop
; 4 cycles total
unpack:
	cbr SBOX_OUTPUT, 0xf0
#endif

	cbr ITEMP, 0xf        ; clear low nibble in s-box input
	or ITEMP, SBOX_OUTPUT ; save low nibble to output register
	brhs sBoxHighNibble   ; do high nibble
	swap ITEMP            ; swap nibbles back
	ret

; apply loaded s-box to every state byte
sBoxLayer:
	; move each byte into a temporary register and apply
	; the s-box procedure for bytes, then move it back
	mov ITEMP, STATE0
	rcall sBoxByte
	mov STATE0, ITEMP

	mov ITEMP, STATE1
	rcall sBoxByte
	mov STATE1, ITEMP

	mov ITEMP, STATE2
	rcall sBoxByte
	mov STATE2, ITEMP

	mov ITEMP, STATE3
	rcall sBoxByte
	mov STATE3, ITEMP
	ret

; rotate the 80-bit key register left by the number in ITEMP
rotate_left_i:
	clr ROTATION_COUNTER
continue_rotate_left_i:
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
	inc ROTATION_COUNTER
	cp ROTATION_COUNTER, ITEMP
	brne continue_rotate_left_i
	ret

; key scheduling
schedule_key:
	; 1: rotate key register left by 61 positions
	ldi ITEMP, 6
	rcall rotate_left_i
	; 3: xor key bits with round counter (as the 2 bytes align while rotating the key register)
	eor KEY4, ROUND_COUNTER
	ldi ITEMP, 55
	rcall rotate_left_i
	; 2: s-box high nibble of key
	mov ITEMP, KEY0
	rcall sBoxHighNibble
	mov KEY0, ITEMP
	; increment round counter
	inc ROUND_COUNTER
	ret

; apply last computed round key to the full 8-byte state in SRAM
addRoundKey:
	clr KEY_INDEX
addRoundKey_byte:
	ld STATE0, X
	eor STATE0, KEY0
	st X+, STATE0
	inc KEY_INDEX
	; rotate key register to next byte
	ldi ITEMP, 8
	rcall rotate_left_i
	; loop over 8 bytes
	cpi KEY_INDEX, 8
	brne addRoundKey_byte

	; rotate key register to align with the start of the block
	ldi ITEMP, 16
	rjmp rotate_left_i

; -------------------------------------
;           utility procedures
; -------------------------------------

; prepare for encryption or decryption
setup:
	; clear zero register
	clr ZERO
	; initialize round counter
	ldi ROUND_COUNTER, 1
	; initialize s-box
	ldi ZH, high(SBOX<<1)
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
	; point at high/left 4 bytes
	subi XL, 18
	ret

#ifdef ENCRYPTION
; -------------------------------------
;         encryption procedures
; -------------------------------------

; load 4 consecutive SRAM bytes into state
consecutive_input:
	ld STATE0, X+
	ld STATE1, X+
	ld STATE2, X+
	ld STATE3, X+
	ret

; save output bytes to SRAM from back to front
; leaves 1 byte untouched in between each saved byte
interleaved_output:
	dec XL
	st -X, OUTPUT0
	dec XL
	st -X, OUTPUT1
	dec XL
	st -X, OUTPUT2
	dec XL
	st -X, OUTPUT3
	ret

; apply the s-box and p-layer from state to output registers
SPnet:
	rcall sBoxLayer
	mov ITEMP, STATE3
	rcall pLayerByte
	mov ITEMP, STATE2
	rcall pLayerByte
	mov ITEMP, STATE1
	rcall pLayerByte
	mov ITEMP, STATE0
	rjmp pLayerByte

; encryption function: point X at 8 plaintext input bytes followed by 10 key input bytes
encrypt:
	rcall setup
	encrypt_update:
		; apply round key
		rcall addRoundKey
		subi XL, 8

		; get invSPnet input for high/left 4 bytes
		rcall consecutive_input

		; encrypt high/left 4 bytes using SP-network
		rcall SPnet

		; get next SPnet input for low/right 4 bytes
		rcall consecutive_input

		; save output to SRAM
		rcall interleaved_output

		; encrypt low/right 4 bytes using SP-network
		rcall SPnet

		; save output to SRAM
		adiw XL, 9
		rcall interleaved_output
		dec XL

		; schedule next key
		rcall schedule_key

		cpi ROUND_COUNTER, ROUNDS
		brne encrypt_update
	rjmp addRoundKey
#endif

#ifdef DECRYPTION
; -------------------------------------
;         decryption procedures
; -------------------------------------

; load state bytes from SRAM from back to front
; leaves 1 byte unread in between each loaded byte
interleaved_input:
	dec XL
	ld OUTPUT0, -X
	dec XL
	ld OUTPUT1, -X
	dec XL
	ld OUTPUT2, -X
	dec XL
	ld OUTPUT3, -X
	ret

; save 4 consecutive output bytes to SRAM
consecutive_output:
	st X+, STATE0
	st X+, STATE1
	st X+, STATE2
	st X+, STATE3
	ret

; invert the s-box and p-layer from state to output registers
invSPnet:
	rcall ipLayerByte
	mov STATE3, ITEMP
	rcall ipLayerByte
	mov STATE2, ITEMP
	rcall ipLayerByte
	mov STATE1, ITEMP
	rcall ipLayerByte
	mov STATE0, ITEMP
	rjmp sBoxLayer

; decryption function: point X at 8 ciphertext input bytes followed by 10 key input bytes
decrypt:
	rcall setup

	; schedule key for last round
	schedule_last_key:
		rcall schedule_key
		cpi ROUND_COUNTER, ROUNDS
		brne schedule_last_key

	; initialize inv s-box
	ldi ZH, high(INVSBOX<<1)

	; start round
	decrypt_update:
		; apply round key
		rcall addRoundKey

		; get invSPnet input for high/left 4 bytes
		rcall interleaved_input

		; decrypt high/left 4 bytes using SP-network
		rcall invSPnet

		; get next invSPnet input for low/right bytes
		adiw XL, 9
		rcall interleaved_input
		dec XL

		; save output to SRAM
		rcall consecutive_output

		; decrypt low/right 4 bytes using SP-network
		rcall invSPnet

		; save output to SRAM
		rcall consecutive_output
		subi XL, 8

		; rotate key register to align with next input and schedule next key
		inv_schedule_key:
			dec ROUND_COUNTER
			; 2: inv s-box high nibble of key
			mov ITEMP, KEY0
			rcall sBoxHighNibble
			mov KEY0, ITEMP
			; 1: rotate key register left by 19 positions
			ldi ITEMP, 17
			rcall rotate_left_i
			; 3: xor key bits with round counter (as the 2 bytes align while rotating the key register)
			eor KEY5, ROUND_COUNTER
			ldi ITEMP, 2
			rcall rotate_left_i

		cpi ROUND_COUNTER, 1
		brne decrypt_update
	rjmp addRoundKey
#endif
