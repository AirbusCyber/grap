#!/usr/bin/env python

import idaapi

#
# Types of instructions
#

# Jump instructions
JMPS = (
    idaapi.NN_jmp,      # Jump
    idaapi.NN_jmpfi,    # Indirect Far Jump
    idaapi.NN_jmpni,    # Indirect Near Jump
    idaapi.NN_jmpshort  # Jump Short (not used)
)

# Conditional jump instructions
CJMPS = (
    idaapi.NN_ja,       # Jump if Above (CF=0 & ZF=0)
    idaapi.NN_jae,      # Jump if Above or Equal (CF=0)
    idaapi.NN_jb,       # Jump if Below (CF=1)
    idaapi.NN_jbe,      # Jump if Below or Equal (CF=1 | ZF=1)
    idaapi.NN_jc,       # Jump if Carry (CF=1)
    idaapi.NN_jcxz,     # Jump if CX is 0
    idaapi.NN_jecxz,    # Jump if ECX is 0
    idaapi.NN_jrcxz,    # Jump if RCX is 0
    idaapi.NN_je,       # Jump if Equal (ZF=1)
    idaapi.NN_jg,       # Jump if Greater (ZF=0 & SF=OF)
    idaapi.NN_jge,      # Jump if Greater or Equal (SF=OF)
    idaapi.NN_jl,       # Jump if Less (SF!=OF)
    idaapi.NN_jle,      # Jump if Less or Equal (ZF=1 | SF!=OF)
    idaapi.NN_jna,      # Jump if Not Above (CF=1 | ZF=1)
    idaapi.NN_jnae,     # Jump if Not Above or Equal (CF=1)
    idaapi.NN_jnb,      # Jump if Not Below (CF=0)
    idaapi.NN_jnbe,     # Jump if Not Below or Equal (CF=0 & ZF=0)
    idaapi.NN_jnc,      # Jump if Not Carry (CF=0)
    idaapi.NN_jne,      # Jump if Not Equal (ZF=0)
    idaapi.NN_jng,      # Jump if Not Greater (ZF=1 | SF!=OF)
    idaapi.NN_jnge,     # Jump if Not Greater or Equal (ZF=1)
    idaapi.NN_jnl,      # Jump if Not Less (SF=OF)
    idaapi.NN_jnle,     # Jump if Not Less or Equal (ZF=0 & SF=OF)
    idaapi.NN_jno,      # Jump if Not Overflow (OF=0)
    idaapi.NN_jnp,      # Jump if Not Parity (PF=0)
    idaapi.NN_jns,      # Jump if Not Sign (SF=0)
    idaapi.NN_jnz,      # Jump if Not Zero (ZF=0)
    idaapi.NN_jo,       # Jump if Overflow (OF=1)
    idaapi.NN_jp,       # Jump if Parity (PF=1)
    idaapi.NN_jpe,      # Jump if Parity Even (PF=1)
    idaapi.NN_jpo,      # Jump if Parity Odd  (PF=0)
    idaapi.NN_js,       # Jump if Sign (SF=1)
    idaapi.NN_jz,       # Jump if Zero (ZF=1)
    idaapi.NN_loopw,    # Loop while ECX != 0
    idaapi.NN_loop,     # Loop while CX != 0
    idaapi.NN_loopd,    # Loop while ECX != 0
    idaapi.NN_loopq,    # Loop while RCX != 0
    idaapi.NN_loopwe,   # Loop while CX != 0 and ZF=1
    idaapi.NN_loope,    # Loop while rCX != 0 and ZF=1
    idaapi.NN_loopde,   # Loop while ECX != 0 and ZF=1
    idaapi.NN_loopqe,   # Loop while RCX != 0 and ZF=1
    idaapi.NN_loopwne,  # Loop while CX != 0 and ZF=0
    idaapi.NN_loopne,   # Loop while rCX != 0 and ZF=0
    idaapi.NN_loopdne,  # Loop while ECX != 0 and ZF=0
    idaapi.NN_loopqne   # Loop while RCX != 0 and ZF=0
)

# Return instructions
RETS = (
    idaapi.NN_retn,   # Return Near from Procedure
    idaapi.NN_retf,   # Return Far from Procedure
    idaapi.NN_retnw,
    idaapi.NN_retnd,
    idaapi.NN_retnq,
    idaapi.NN_retfw,
    idaapi.NN_retfd,
    idaapi.NN_retfq
)

# Call Instructions
CALLS = (
    idaapi.NN_call,    # Call Procedure
    idaapi.NN_callfi,  # Indirect Call Far Procedure
    idaapi.NN_callni   # Indirect Call Near Procedure
)

#
# Types of operands
#

# Memory types
OP_MEM = (
    idaapi.o_near,
    idaapi.o_far
)
