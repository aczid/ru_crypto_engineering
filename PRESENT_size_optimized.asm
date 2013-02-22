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

; scratch space
.def TEMP0 = r10
.def TEMP1 = r11
.def TEMP2 = r12
.def TEMP3 = r13
.def TEMP4 = r14
.def TEMP5 = r15

; State (input/output)
.def STATE0 = r16
.def STATE1 = r17
.def STATE2 = r18
.def STATE3 = r19
.def STATE4 = r20
.def STATE5 = r21
.def STATE6 = r22
.def STATE7 = r23

.def ROUND_COUNTER = r24
.def ITEMP = r25

; registers r26 and up are X, Y and Z

.org 256
SBOX:.db 0xc,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2

addRoundKey:
	; state ^= roundkey (first 8 bytes of key register)
	eor STATE0, KEY0
	eor STATE1, KEY1
	eor STATE2, KEY2
	eor STATE3, KEY3
	eor STATE4, KEY4
	eor STATE5, KEY5
	eor STATE6, KEY6
	eor STATE7, KEY7
	ret

; pLayerByte
; approach stolen from KULeuven implementation

; splices 1 input byte over 4 output bytes, which will then each hold 2 bits
; following a 4-bit period in the byte

; after 4 calls from different input registers we will have collected 4
; completed output bytes following this 4-bit period

; uses T (transfer) flag to re-do this block twice
setup_redo_pLayerByte:
	clt ; clear T flag
	rjmp redo_pLayerByte ; do the second part
pLayerByte:
	set ; set T flag
	; fall through
redo_pLayerByte:
	ror ITEMP ; move bit into carry
	ror TEMP0 ; move bit into output register
	ror ITEMP ; etc
	ror TEMP1
	ror ITEMP
	ror TEMP2
	ror ITEMP
	ror TEMP3
	brts setup_redo_pLayerByte ; redo this block? (if T flag set)
	; would have another ror to ITEMP here for invpLayer
	ret

; sBoxByte
; applying the s-box nibble-wise allows us to reuse the second half of the
; procedure as its own procedure when key scheduling
sBoxByte:
	; input (low nibble)
	mov ZL, ITEMP   ; load input
	cbr ZL, 0xf0    ; clear high nibble in input

	; output (low nibble)
	lpm TEMP0, Z    ; load s-box output into temp register
	cbr ITEMP, 0xf  ; clear low nibble in output register
	or ITEMP, TEMP0 ; save low nibble to output register

	; fall through
sBoxHighNibble:
	; input (high nibble)
	mov  ZL, ITEMP  ; load input
	cbr  ZL, 0xf    ; clear low nibble in input
	swap ZL         ; move high nibble to low nibble in input

	; output (high nibble)
	lpm TEMP0, Z    ; load s-box output into temp register
	swap TEMP0      ; move low nibble of s-box output to high nibble
	cbr ITEMP, 0xf0 ; clear high nibble in output
	or ITEMP, TEMP0 ; save high nibble to output

	ret

; the main function called by the wrapper provided by the instructors
encrypt:
	init:
		; load plaintext from SRAM
		ld STATE0, X+
		ld STATE1, X+
		ld STATE2, X+
		ld STATE3, X+
		ld STATE4, X+
		ld STATE5, X+
		ld STATE6, X+
		ld STATE7, X+

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

		; initialize s-box
		ldi ZH, high(SBOX<<1)
		; silliest optimization:
		; according to Atmel documentation we can count on registers being
		; initialized to 0 on reset
		;clr ROUND_COUNTER
		
	update:
		inc ROUND_COUNTER
		rcall addRoundKey
		; apply s-box to every state byte
		sBoxLayer:
			; move each byte into a temporary register and apply the s-box
			; procedure for bytes
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

			mov ITEMP, STATE4
			rcall sBoxByte
			mov STATE4, ITEMP

			mov ITEMP, STATE5
			rcall sBoxByte
			mov STATE5, ITEMP

			mov ITEMP, STATE6
			rcall sBoxByte
			mov STATE6, ITEMP

			mov ITEMP, STATE7
			rcall sBoxByte
			mov STATE7, ITEMP

		; permutes bit positions
		; stolen from KULeuven implementation and slightly optimized
		pLayer:
			; map first 4 bytes on even bytes
			mov ITEMP,STATE7
			rcall pLayerByte
			mov ITEMP,STATE6
			rcall pLayerByte
			mov ITEMP,STATE5
			rcall pLayerByte
			mov ITEMP,STATE4
			rcall pLayerByte

			; copy even bytes into position
			mov STATE7,TEMP0
			mov STATE5,TEMP1
			mov ITEMP,STATE3 ; prepare input for next bytes
			mov STATE3,TEMP2
			mov STATE4,TEMP3 ; save last byte
			
			; map last 4 bytes on odd bytes
			rcall pLayerByte
			mov ITEMP,STATE2
			rcall pLayerByte
			mov ITEMP,STATE1
			rcall pLayerByte
			mov ITEMP,STATE0
			rcall pLayerByte

			mov STATE1,STATE4 ; apply last byte

			; copy odd bytes into position
			mov STATE6,TEMP0
			mov STATE4,TEMP1
			mov STATE2,TEMP2
			mov STATE0,TEMP3

		; schedule key for next round - explained inside
		schedule_key:
			; 1: rotate key register left by 61 positions
			clr ITEMP
			rotate_left_61:
				; rotates every bit to the left
				; takes carry bit using lsl then moves it through the registers
				; finally adds it to the first zeroed bit of the lsl'd register
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
				; this register is never changed from its initial value of 0
				; so we only add the carry bit that fell out at the last rol
				; to the lowest bit (which was zeroed by that instruction)
				adc KEY9, TEMP4
				inc ITEMP
				; 3: xor bits 19..15 of key register with round counter
				cpi ITEMP, 6
				; after 6 shifts
				brne continue_rotate_left_61
				; XOR key[4] with round counter as the bits line up here
				; after 55 more rotations these bits will be in places 19..15
				eor KEY4, ROUND_COUNTER 
			; fallthrough
			continue_rotate_left_61:
				cpi ITEMP, 61
				brne rotate_left_61
			; 2: sbox high nibble of key
			mov ITEMP, KEY0
			rcall sBoxHighNibble
			mov KEY0, ITEMP

		; check round counter, break after 31 iterations
		cpi ROUND_COUNTER, 31
		brne trampoline ; continue
		rjmp final      ; break
	trampoline:
		; conditional branch instructions can only handle relative jumps and we
		; are out of reach for a relative jump to update at this point
		rjmp update

	final:
		; apply final round key
		rcall addRoundKey

		; copy output to SRAM
		subi XL, 18
		st X+, STATE0
		st X+, STATE1
		st X+, STATE2
		st X+, STATE3
		st X+, STATE4
		st X+, STATE5
		st X+, STATE6
		st X+, STATE7
	ret
