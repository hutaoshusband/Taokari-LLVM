"""Shared MIR guard-blob byte signatures (x86-64 machine code)."""
from __future__ import annotations

JUNK = bytes.fromhex("9c 50 80 34 24 5a 80 34 24 5a 58 9d")
SUB_ADD_LEA = bytes.fromhex(
    "9c 50 48 89 e0 48 8d 40 13 48 83 e8 13 58 9d")
SUB_DOUBLE_NEG = bytes.fromhex("9c 50 48 f7 d8 48 f7 d8 58 9d")
SUB_DOUBLE_NOT = bytes.fromhex("9c 50 48 f7 d0 48 f7 d0 58 9d")
SUB_VARIANTS = (SUB_ADD_LEA, SUB_DOUBLE_NEG, SUB_DOUBLE_NOT)
DIRTY_STACK = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 01 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_STACK_DEC = bytes.fromhex(
    "9c 50 51 48 89 e0 48 8d 48 ff 48 0f af c1 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_SHIFT = bytes.fromhex(
    "9c 50 51 48 89 e0 48 d1 e0 a8 01 74 08 0f 0b eb fe cc f1 0f 0b 59 58 9d"
)
DIRTY_VARIANTS = (DIRTY_STACK, DIRTY_STACK_DEC, DIRTY_SHIFT)
