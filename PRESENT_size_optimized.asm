; Key registers
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

; pLayer output
.def OUTPUT0 = r10
.def OUTPUT1 = r11
.def OUTPUT2 = r12
.def OUTPUT3 = r13

; Never used but needed for its 0 value to add carry bits with adc
.def ZERO = r14

; State (input/output)
.def STATE0 = r15
.def STATE1 = r16
.def STATE2 = r17
.def STATE3 = r18

; Shared register for SBOX output and to count key register rotations
.def SBOX_OUTPUT = r19
.def ROTATION_COUNTER = r19

; The round counter
.def ROUND_COUNTER = r20

; Register we can use for immediate values
.def ITEMP = r21

; registers 22..25 are unused
; registers r26 and up are X, Y and Z

.org 256
SBOX:   .db 0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xF,0x8,0x4,0x7,0x1,0x2
.org 512
          ; 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
INVSBOX:.db 0x5,0xe,0xf,0x8,0xc,0x1,0x2,0xd,0xb,0x4,0x6,0x3,0x0,0x7,0x9,0xa

addRoundKey:
	; state ^= roundkey (top 4 bytes of key register)
	eor STATE0, KEY0
	eor STATE1, KEY1
	eor STATE2, KEY2
	eor STATE3, KEY3
	ret

; pLayerByte
; approach stolen from KULeuven implementation

; splices 1 input byte over 4 output bytes, which will then each hold 2 bits
; following a 4-bit period in the input

; after 4 calls from different input registers we will have collected 4
; completed output bytes following this 4-bit period

; uses H (half-carry) flag to re-do this block twice
setup_redo_pLayerByte:
	clh ; clear H flag
	rjmp redo_pLayerByte ; do the second part
ipLayerByte:
	seh ; set H flag
	rjmp redo_pLayerByte
pLayerByte:
	seh ; set H flag
	ror ITEMP   ; move bit into carry
	; fall through
redo_pLayerByte:
	ror OUTPUT0 ; move bit into output register
	ror ITEMP   ; etc
	ror OUTPUT1
	ror ITEMP
	ror OUTPUT2
	ror ITEMP
	ror OUTPUT3
	ror ITEMP
	brhs setup_redo_pLayerByte ; redo this block? (if H flag set)
	; for invpLayer
	ret

; sBoxByte
; applying the s-box nibble-wise allows us to reuse the second half of the
; procedure as its own procedure when key scheduling
; reads from and writes to ITEMP
sBoxByte:
	; input (low nibble)
	mov ZL, ITEMP   ; load input
	cbr ZL, 0xf0    ; clear high nibble in input

	; output (low nibble)
	lpm SBOX_OUTPUT, Z    ; load s-box output into temp register
	cbr ITEMP, 0xf        ; clear low nibble in output register
	or ITEMP, SBOX_OUTPUT ; save low nibble to output register

	; fall through
sBoxHighNibble:
	; input (high nibble)
	mov  ZL, ITEMP  ; load input
	cbr  ZL, 0xf    ; clear low nibble in input
	swap ZL         ; move high nibble to low nibble in input

	; output (high nibble)
	lpm SBOX_OUTPUT, Z    ; load s-box output into temp register
	swap SBOX_OUTPUT      ; move low nibble of s-box output to high nibble
	cbr ITEMP, 0xf0       ; clear high nibble in output
	or ITEMP, SBOX_OUTPUT ; save high nibble to output

	ret

; load 4 consecutive input bytes into state
consecutive_input:
	ld STATE0, X+
	ld STATE1, X+
	ld STATE2, X+
	ld STATE3, X+
	ret

; rotates key register left by the number in ITEMP
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

; saves state bytes from back to front
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

inv_schedule_key:
	dec ROUND_COUNTER
	; 2: inv s-box high nibble of key
	mov ITEMP, KEY0
	rcall sBoxHighNibble
	mov KEY0, ITEMP
	; 1: rotate key register left by 61 positions
	ldi ITEMP, 25
	rcall rotate_left_i
	; 3: xor key bits with round counter
	eor KEY4, ROUND_COUNTER
	ldi ITEMP, 74
	rcall rotate_left_i
	; increment round counter
	ret

; apply s-box to every state byte
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

; load key from SRAM, back to front
load_key:
	ld KEY9, -X
	ld KEY8, -X
	ld KEY7, -X
	ld KEY6, -X
	ld KEY5, -X
	ld KEY4, -X
	ld KEY3, -X
	ld KEY2, -X
	ld KEY1, -X
	ld KEY0, -X
	ret

; the main function called by the wrapper provided by the instructors
; uses the T flag to transfer control to even and odd output procedures which
; do the final interleaved placement of the pLayer output in SRAM
encrypt:
	encrypt_init:
		; initialize round counter
		ldi ROUND_COUNTER, 1
		; initialize s-box
		ldi ZH, high(SBOX<<1)
		; load first 4 input bytes (high/left part)
		rcall consecutive_input
		; point at the end of the key bytes
		adiw XL, 14
		; load key from SRAM, back to front
		rcall load_key
		; point at the second 4 input bytes (low/right part)
		subi XL, 4
		; start round
		rjmp encrypt_update
	; copy odd bytes into position and set up for the second part of the round
	odd_output:
		; load next state bytes (low/right part)
		rcall consecutive_input
		; copy odd bytes into position
		rcall interleaved_output
		; rotate key register by 4 bytes to align its first 4 bytes with
		; the next 4 bytes of input
		ldi ITEMP, 32
		rcall rotate_left_i
		; set T flag to transfer control to even_output after this round
		set
		; do next 4 bytes
		; fall through
	; main round procedure
	encrypt_update:
		; apply round key and s-box
		rcall addRoundKey
		rcall sBoxLayer

		; permutes bit positions in the state following a 4-bit period
		; stolen from KULeuven implementation and optimized for size
		pLayer:
			; map output bytes
			mov ITEMP,STATE3
			rcall pLayerByte
			mov ITEMP,STATE2
			rcall pLayerByte
			mov ITEMP,STATE1
			rcall pLayerByte
			mov ITEMP,STATE0
			rcall pLayerByte

		; check the T flag
		; if it's not set we are working on the high/left block
		brtc odd_output

		; otherwise, we are working on the low/right block
		even_output:
			; copy even state bytes into position
			adiw XL, 9
			rcall interleaved_output
			dec XL
			; load next 4 high/left input bytes
			rcall consecutive_input
			; rotate back key register
			ldi ITEMP, 48
			rcall rotate_left_i
			; clear T flag to send the next round through the
			; odd_output procedure first
			clt
		; fall through

		; schedule key for next round
		rcall schedule_key

		; check round counter, break when it reaches 32
		; (meaning the key scheduled is k_32)
		cpi ROUND_COUNTER, 32
		brne encrypt_update ; do next round
		; fall through
	encrypt_final:
		; apply final round key and output (high/left)
		rcall final_part

		; load low/right bytes
		rcall consecutive_input
		; adjust key register
		ldi ITEMP, 32
		rcall rotate_left_i
		; apply final round key and output (low/right)
		rcall final_part
	ret

consecutive_output:
	st X+, OUTPUT0
	st X+, OUTPUT1
	st X+, OUTPUT2
	st X+, OUTPUT3
	ret

; do the last round key and save output
final_part:
	rcall addRoundKey
	subi XL, 4

	; saves 4 consecutive bytes to RAM
	rcall state_to_output
	rcall consecutive_output
	ret

state_to_output:
	mov OUTPUT0, STATE0
	mov OUTPUT1, STATE1
	mov OUTPUT2, STATE2
	mov OUTPUT3, STATE3
	ret

; load 4 consecutive input bytes into state
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

roundkey_ram:
	rcall addRoundkey
	rcall state_to_output
	rcall consecutive_output
	ret

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

decrypt:
	; initialize round_counter
	ldi ROUND_COUNTER, 1
	; initialize s-box
	ldi ZH, high(SBOX<<1)
	; point at the end of the key bytes
	adiw XL, 18
	; load key from SRAM, back to front
	rcall load_key

	; schedule key for last round
	schedule_last_key:
		rcall schedule_key
		cpi ROUND_COUNTER, 32
		brne schedule_last_key

	; initialize inv s-box
	ldi ZH, high(INVSBOX<<1)
	
	; start round
	decrypt_update:
		subi XL, 8
		rcall consecutive_input
		subi XL, 4
		rcall roundkey_ram

		rcall consecutive_input
		subi XL, 4
		ldi ITEMP, 32
		rcall rotate_left_i
		rcall roundkey_ram

		rcall interleaved_input
		
		rcall invSPnet

		; split around here if at all possible

		adiw XL, 9
		rcall interleaved_input
		dec XL
		rcall consecutive_output

		rcall invSPnet

		rcall consecutive_output

		ldi ITEMP, 48
		rcall rotate_left_i
		rcall inv_schedule_key

		cpi ROUND_COUNTER, 1
		brne decrypt_update
	ret
 
	
