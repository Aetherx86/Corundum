// Copyright (c) 2026 jk9576. All rights reserved.
// Corundum: Comptime-Verified eBPF Bytecode Assembler & CFG Verifier
// Licensed under the MIT License.

const std = @import("std");
pub const ebpf = @import("ebpf.zig");

pub export fn corundum_verify_slice(ptr: [*]const ebpf.Insn, count: usize) i32 {
    const slice = ptr[0..count];
    ebpf.Verifier.verify(slice) catch |err| {
        return switch (err) {
            error.ProgramEmpty => -1,
            error.ProgramTooLarge => -2,
            error.MissingExitInstruction => -3,
            error.CyclicJumpDetected => -4,
            error.JumpOutOfBounds => -5,
            error.UnalignedMemoryAccess => -6,
            error.ReadOnlyRegisterModified => -7,
            error.UninitializedRegisterRead => -8,
            error.DivisionByZero => -9,
        };
    };
    return 0; // PASS
}

pub fn main() !void {
    const prog = [_]ebpf.Insn{
        .{ .alu_imm = .{ .op = .mov, .is_64 = true, .dst = .r0, .imm = 0 } },
        .{ .alu_imm = .{ .op = .add, .is_64 = true, .dst = .r0, .imm = 42 } },
        .exit,
    };

    // Compile-time verification proof
    ebpf.Verifier.comptimeVerify(&prog);

    try ebpf.Verifier.verify(&prog);
    std.debug.print("Corundum: eBPF program verified successfully with 0 violations.\n", .{});
}

test "comptime eBPF verification succeeds on safe DAG" {
    const valid_prog = [_]ebpf.Insn{
        .{ .alu_imm = .{ .op = .mov, .is_64 = true, .dst = .r0, .imm = 0 } },
        .{ .branch_imm = .{ .op = .jeq, .dst = .r0, .imm = 0, .off = 1 } },
        .{ .alu_imm = .{ .op = .mov, .is_64 = true, .dst = .r0, .imm = 1 } },
        .exit,
    };

    ebpf.Verifier.comptimeVerify(&valid_prog);
    try ebpf.Verifier.verify(&valid_prog);
}

test "verifier detects uninitialized register read" {
    const bad_prog = [_]ebpf.Insn{
        .{ .alu_reg = .{ .op = .add, .is_64 = true, .dst = .r0, .src = .r7 } }, // r7 uninitialized!
        .exit,
    };

    const res = ebpf.Verifier.verify(&bad_prog);
    try std.testing.expectError(error.UninitializedRegisterRead, res);
}

test "verifier detects backward/cyclic jump violation" {
    const cycle_prog = [_]ebpf.Insn{
        .{ .alu_imm = .{ .op = .mov, .is_64 = true, .dst = .r0, .imm = 0 } },
        .{ .jump = .{ .off = -1 } }, // Backward jump!
        .exit,
    };

    const res = ebpf.Verifier.verify(&cycle_prog);
    try std.testing.expectError(error.CyclicJumpDetected, res);
}

test "verifier detects unaligned 64-bit memory load" {
    const unaligned_prog = [_]ebpf.Insn{
        .{ .alu_imm = .{ .op = .mov, .is_64 = true, .dst = .r0, .imm = 0 } },
        .{ .load = .{ .dst = .r2, .src = .r10, .off = -5, .size = 3 } }, // 8-byte load at off -5 is unaligned!
        .exit,
    };

    const res = ebpf.Verifier.verify(&unaligned_prog);
    try std.testing.expectError(error.UnalignedMemoryAccess, res);
}
