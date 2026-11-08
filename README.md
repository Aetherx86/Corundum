# Corundum

Comptime-Verified eBPF Bytecode Assembler & CFG Verifier

A domain-specific assembler and safety validator that encodes, disassembles, and verifies Linux eBPF / BPF-extended instruction sequences entirely at compile time using Zig.

## Architecture

- Comptime Verification: Models the eBPF register set (R0 through R10) and DAG invariants directly within the Zig type system. Any cyclic jump, unaligned 64-bit memory load, or uninitialized register read triggers a compile error before binary emission.
- Exhaustive Tagged Unions: Uses `union(enum)` variants for ALU, branch, memory, and call instructions, guaranteeing mathematical rigor and zero illegal state transitions.
- Zero External Dependencies: Builds both a standalone CLI verification binary and a C-ABI shared library (`libcorundum.so` / `libcorundum.dylib`) in a single step (`zig build`).
- Hostile DAG Defense: Bounds maximum instruction sequences and enforces forward-progress branch invariants to prevent unbounded execution loops.

## Building and Testing

```bash
# Run test suite with comptime proofs
zig build test

# Build CLI utility and shared library
zig build -Doptimize=ReleaseFast
```

## C-ABI Interface

```c
int32_t corundum_verify_slice(const Insn* ptr, size_t count);
```

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
