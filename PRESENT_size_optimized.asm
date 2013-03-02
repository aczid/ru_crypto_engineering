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
; Size optimized version 1 - February 2013
; Code size (total):           410 bytes + 16 bytes for both packed s-boxes
; RAM words:                    18
; Cycle count (encryption):  90725
; Cycle count (decryption): 102257

; USE
; Point X at 8 input bytes followed by 10 key bytes and call encrypt or decrypt
; After having called encryption or decryption X will point to the end of the input

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

; Register we can use for immediate values
.def ITEMP = r21

; registers r22..r25 are unused
; registers r26..r31 are X, Y and Z

; the Z register is used to point to these s-box tables
.org 256
SBOX:   .db 0x0c,0x05,0x06,0x0b,0x09,0x00,0x0a,0x0d,0x03,0x0e,0x0f,0x08,0x04,0x07,0x01,0x02
.org 512
INVSBOX:.db 0x05,0x0e,0x0f,0x08,0x0c,0x01,0x02,0x0d,0x0b,0x04,0x06,0x03,0x00,0x07,0x09,0x0a

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
	clh ; clear H flag
	rjmp continue_pLayerByte ; do the second part
ipLayerByte:
	seh ; set H flag
	rjmp continue_pLayerByte
pLayerByte:
	seh ; set H flag
	ror ITEMP   ; move bit into carry
	; fall through
continue_pLayerByte:
	ror OUTPUT0 ; move bit into output register
	ror ITEMP   ; etc
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
	clh
	swap ITEMP; swap nibbles
	rjmp sBoxLowNibble
sBoxByte:
	seh
	; fall through
sBoxLowNibble:
	; input (low nibble)
	mov ZL, ITEMP   ; load s-box input
	cbr ZL, 0xf0    ; clear high nibble in s-box input

	; output (low nibble)
	lpm SBOX_OUTPUT, Z ; get s-box output
	cbr ITEMP, 0xf    ; clear low nibble in s-box input
	or ITEMP, SBOX_OUTPUT ; save low nibble to output register
	brhs sBoxHighNibble
	swap ITEMP ; swap nibbles
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

; rotate key register left by the number in ITEMP
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
	; 3: xor key bits with round counter
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

; load 4 consecutive SRAM bytes into state
consecutive_input:
	ld STATE0, X+
	ld STATE1, X+
	ld STATE2, X+
	ld STATE3, X+
	ret

; save 4 consecutive output bytes to SRAM
consecutive_output:
	st X+, OUTPUT0
	st X+, OUTPUT1
	st X+, OUTPUT2
	st X+, OUTPUT3
	ret

; move current state to output registers
state_to_output:
	mov OUTPUT0, STATE0
	mov OUTPUT1, STATE1
	mov OUTPUT2, STATE2
	mov OUTPUT3, STATE3
	ret

; load input and apply current round key to 4 bytes in SRAM
roundkey_ram:
	rcall consecutive_input
	subi XL, 4
	; state ^= roundkey (top 4 bytes of key register)
	eor STATE0, KEY0
	eor STATE1, KEY1
	eor STATE2, KEY2
	eor STATE3, KEY3
	rcall state_to_output
	rcall consecutive_output
	ret

; apply last computed round key to the full state
addRoundKey:
	; apply round key to high/left 4 bytes
	rcall roundkey_ram
	; rotate key register to add round key to low/right 4 bytes
	ldi ITEMP, 32
	rcall rotate_left_i
	; apply round key to low/right 4 bytes
	rcall roundkey_ram
	ret

; -------------------------------------
;           utility procedures
; -------------------------------------

; prepare for encryption or decryption
setup:
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

; -------------------------------------
;         encryption procedures
; -------------------------------------

; saves output bytes to SRAM from back to front
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
	rcall pLayerByte
	ret

; encryption function: point X at 8 plaintext input bytes followed by 10 key input bytes
encrypt:
	rcall setup
	encrypt_update:
		; apply round key
		rcall addRoundKey
		subi XL, 8

		; load high/left 4 bytes
		rcall consecutive_input

		; encrypt high/left 4 bytes using SP-network
		rcall SPnet

		; load low/right 4 bytes
		rcall consecutive_input

		; save output to SRAM
		rcall interleaved_output

		; encrypt using SP-network
		rcall SPnet

		; save output to SRAM
		adiw XL, 9
		rcall interleaved_output
		dec XL

		; rotate key register to align with high/left part
		ldi ITEMP, 48
		rcall rotate_left_i

		; schedule next key
		rcall schedule_key

		cpi ROUND_COUNTER, 32
		brne encrypt_update
	rcall addRoundKey
	ret

; -------------------------------------
;         decryption procedures
; -------------------------------------

; loads state bytes from SRAM from back to front
; leaves 1 byte unread in between each loaded byte
interleaved_input:
	dec XL
	ld STATE0, -X
	dec XL
	ld STATE1, -X
	dec XL
	ld STATE2, -X
	dec XL
	ld STATE3, -X
	ret

; invert the s-box and p-layer from state to output registers
invSPnet:
	rcall state_to_output
	rcall ipLayerByte
	mov STATE3, ITEMP
	rcall ipLayerByte
	mov STATE2, ITEMP
	rcall ipLayerByte
	mov STATE1, ITEMP
	rcall ipLayerByte
	mov STATE0, ITEMP
	rcall sBoxLayer
	rcall state_to_output
	ret

; decryption function: point X at 8 ciphertext input bytes followed by 10 key input bytes
decrypt:
	rcall setup

	; schedule key for last round
	schedule_last_key:
		rcall schedule_key
		cpi ROUND_COUNTER, 32
		brne schedule_last_key

	; initialize inv s-box
	ldi ZH, high(INVSBOX<<1)

	; start round
	decrypt_update:
		; apply round key
		rcall addRoundKey

		; get invSPnet input for high/left bytes
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
			mov ITEMP, KEY6
			rcall sBoxHighNibble
			mov KEY6, ITEMP
			; 1: rotate key register left by 48+19=67 positions
			ldi ITEMP, 1
			rcall rotate_left_i
			; 3: xor key bits with round counter
			eor KEY3, ROUND_COUNTER
			ldi ITEMP, 66
			rcall rotate_left_i

		cpi ROUND_COUNTER, 1
		brne decrypt_update
	rcall addRoundKey
	ret
