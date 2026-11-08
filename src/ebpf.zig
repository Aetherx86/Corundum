// Copyright (c) 2026 jk9576. All rights reserved.
// Corundum: Comptime-Verified eBPF Bytecode Assembler & CFG Verifier
// Licensed under the MIT License.

const std = @import("std");

pub const Reg = enum(u4) {
    r0 = 0, // Return value
    r1 = 1, // Arg 1
    r2 = 2, // Arg 2
    r3 = 3, // Arg 3
    r4 = 4, // Arg 4
    r5 = 5, // Arg 5
    r6 = 6, // Callee-saved 1
    r7 = 7, // Callee-saved 2
    r8 = 8, // Callee-saved 3
    r9 = 9, // Callee-saved 4
    r10 = 10, // Read-only stack frame pointer
    _,

    pub inline fn isReadOnly(self: Reg) bool {
        return self == .r10;
    }
};

pub const Class = enum(u3) {
    ld = 0x00,
    ldx = 0x01,
    st = 0x02,
    stx = 0x03,
    alu32 = 0x04,
    jmp = 0x05,
    jmp32 = 0x06,
    alu64 = 0x07,
};

pub const AluOp = enum(u4) {
    add = 0x0,
    sub = 0x1,
    mul = 0x2,
    div = 0x3,
    or_op = 0x4,
    and_op = 0x5,
    lsh = 0x6,
    rsh = 0x7,
    neg = 0x8,
    mod = 0x9,
    xor_op = 0xa,
    mov = 0xb,
    arsh = 0xc,
    endian = 0xd,
};

pub const JmpOp = enum(u4) {
    ja = 0x0,
    jeq = 0x1,
    jgt = 0x2,
    jge = 0x3,
    jset = 0x4,
    jne = 0x5,
    jsgt = 0x6,
    jsge = 0x7,
    call = 0x8,
    exit = 0x9,
    jlt = 0xa,
    jle = 0xb,
    jslt = 0xc,
    jsle = 0xd,
};

pub const RawInsn = packed struct {
    opcode: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: i32,
};

pub const Insn = union(enum) {
    alu_imm: struct { op: AluOp, is_64: bool, dst: Reg, imm: i32 },
    alu_reg: struct { op: AluOp, is_64: bool, dst: Reg, src: Reg },
    load: struct { dst: Reg, src: Reg, off: i16, size: u2 }, // 0: 1B, 1: 2B, 2: 4B, 3: 8B
    store_imm: struct { dst: Reg, off: i16, imm: i32, size: u2 },
    store_reg: struct { dst: Reg, src: Reg, off: i16, size: u2 },
    branch_imm: struct { op: JmpOp, dst: Reg, imm: i32, off: i16 },
    branch_reg: struct { op: JmpOp, dst: Reg, src: Reg, off: i16 },
    jump: struct { off: i16 },
    call: struct { func_id: i32 },
    exit: void,

    pub fn encode(self: Insn) RawInsn {
        return switch (self) {
            .alu_imm => |a| RawInsn{
                .opcode = (@as(u8, @intFromEnum(a.op)) << 4) | 0x00 | (if (a.is_64) @as(u8, 0x07) else @as(u8, 0x04)),
                .dst = @intFromEnum(a.dst),
                .src = 0,
                .off = 0,
                .imm = a.imm,
            },
            .alu_reg => |a| RawInsn{
                .opcode = (@as(u8, @intFromEnum(a.op)) << 4) | 0x08 | (if (a.is_64) @as(u8, 0x07) else @as(u8, 0x04)),
                .dst = @intFromEnum(a.dst),
                .src = @intFromEnum(a.src),
                .off = 0,
                .imm = 0,
            },
            .load => |l| RawInsn{
                .opcode = 0x61 | (@as(u8, l.size) << 3), // BPF_LDX | BPF_MEM
                .dst = @intFromEnum(l.dst),
                .src = @intFromEnum(l.src),
                .off = l.off,
                .imm = 0,
            },
            .store_imm => |s| RawInsn{
                .opcode = 0x62 | (@as(u8, s.size) << 3), // BPF_ST | BPF_MEM
                .dst = @intFromEnum(s.dst),
                .src = 0,
                .off = s.off,
                .imm = s.imm,
            },
            .store_reg => |s| RawInsn{
                .opcode = 0x63 | (@as(u8, s.size) << 3), // BPF_STX | BPF_MEM
                .dst = @intFromEnum(s.dst),
                .src = @intFromEnum(s.src),
                .off = s.off,
                .imm = 0,
            },
            .branch_imm => |b| RawInsn{
                .opcode = (@as(u8, @intFromEnum(b.op)) << 4) | 0x00 | 0x05, // BPF_JMP | BPF_K
                .dst = @intFromEnum(b.dst),
                .src = 0,
                .off = b.off,
                .imm = b.imm,
            },
            .branch_reg => |b| RawInsn{
                .opcode = (@as(u8, @intFromEnum(b.op)) << 4) | 0x08 | 0x05, // BPF_JMP | BPF_X
                .dst = @intFromEnum(b.dst),
                .src = @intFromEnum(b.src),
                .off = b.off,
                .imm = 0,
            },
            .jump => |j| RawInsn{
                .opcode = 0x05, // BPF_JMP | BPF_JA
                .dst = 0,
                .src = 0,
                .off = j.off,
                .imm = 0,
            },
            .call => |c| RawInsn{
                .opcode = 0x85, // BPF_JMP | BPF_CALL
                .dst = 0,
                .src = 0,
                .off = 0,
                .imm = c.func_id,
            },
            .exit => RawInsn{
                .opcode = 0x95, // BPF_JMP | BPF_EXIT
                .dst = 0,
                .src = 0,
                .off = 0,
                .imm = 0,
            },
        };
    }
};

pub const VerifierError = error{
    ProgramEmpty,
    ProgramTooLarge,
    MissingExitInstruction,
    CyclicJumpDetected,
    JumpOutOfBounds,
    UnalignedMemoryAccess,
    ReadOnlyRegisterModified,
    UninitializedRegisterRead,
    DivisionByZero,
};

pub const Verifier = struct {
    pub fn verify(insns: []const Insn) VerifierError!void {
        if (insns.len == 0) return error.ProgramEmpty;
        if (insns.len > 4096) return error.ProgramTooLarge;

        var has_exit = false;
        var initialized_regs = [11]bool{ false, false, false, false, false, false, false, false, false, false, false };
        initialized_regs[1] = true;  // Context pointer in R1
        initialized_regs[10] = true; // Frame pointer in R10

        for (insns, 0..) |insn, pc| {
            switch (insn) {
                .exit => {
                    has_exit = true;
                    // R0 must be initialized at exit
                    if (!initialized_regs[0]) return error.UninitializedRegisterRead;
                },
                .alu_imm => |a| {
                    if (a.dst.isReadOnly()) return error.ReadOnlyRegisterModified;
                    if (a.op == .div or a.op == .mod) {
                        if (a.imm == 0) return error.DivisionByZero;
                    }
                    if (a.op != .mov and !initialized_regs[@intFromEnum(a.dst)]) {
                        return error.UninitializedRegisterRead;
                    }
                    initialized_regs[@intFromEnum(a.dst)] = true;
                },
                .alu_reg => |a| {
                    if (a.dst.isReadOnly()) return error.ReadOnlyRegisterModified;
                    if (!initialized_regs[@intFromEnum(a.src)]) return error.UninitializedRegisterRead;
                    if (a.op != .mov and !initialized_regs[@intFromEnum(a.dst)]) {
                        return error.UninitializedRegisterRead;
                    }
                    initialized_regs[@intFromEnum(a.dst)] = true;
                },
                .load => |l| {
                    if (l.dst.isReadOnly()) return error.ReadOnlyRegisterModified;
                    if (!initialized_regs[@intFromEnum(l.src)]) return error.UninitializedRegisterRead;
                    // Alignment check: 8-byte loads must be 8-byte aligned, etc.
                    const align_bytes: i16 = switch (l.size) {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                    };
                    if (@rem(l.off, align_bytes) != 0) return error.UnalignedMemoryAccess;
                    initialized_regs[@intFromEnum(l.dst)] = true;
                },
                .store_imm => |s| {
                    if (!initialized_regs[@intFromEnum(s.dst)]) return error.UninitializedRegisterRead;
                    const align_bytes: i16 = switch (s.size) {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                    };
                    if (@rem(s.off, align_bytes) != 0) return error.UnalignedMemoryAccess;
                },
                .store_reg => |s| {
                    if (!initialized_regs[@intFromEnum(s.dst)]) return error.UninitializedRegisterRead;
                    if (!initialized_regs[@intFromEnum(s.src)]) return error.UninitializedRegisterRead;
                    const align_bytes: i16 = switch (s.size) {
                        0 => 1,
                        1 => 2,
                        2 => 4,
                        3 => 8,
                    };
                    if (@rem(s.off, align_bytes) != 0) return error.UnalignedMemoryAccess;
                },
                .branch_imm => |b| {
                    if (!initialized_regs[@intFromEnum(b.dst)]) return error.UninitializedRegisterRead;
                    // Enforce forward-only / DAG invariant to prevent loops
                    if (b.off <= 0) return error.CyclicJumpDetected;
                    const target = pc + 1 + @as(usize, @intCast(b.off));
                    if (target >= insns.len) return error.JumpOutOfBounds;
                },
                .branch_reg => |b| {
                    if (!initialized_regs[@intFromEnum(b.dst)]) return error.UninitializedRegisterRead;
                    if (!initialized_regs[@intFromEnum(b.src)]) return error.UninitializedRegisterRead;
                    if (b.off <= 0) return error.CyclicJumpDetected;
                    const target = pc + 1 + @as(usize, @intCast(b.off));
                    if (target >= insns.len) return error.JumpOutOfBounds;
                },
                .jump => |j| {
                    if (j.off <= 0) return error.CyclicJumpDetected;
                    const target = pc + 1 + @as(usize, @intCast(j.off));
                    if (target >= insns.len) return error.JumpOutOfBounds;
                },
                .call => {
                    // Clobbers R1-R5, produces return in R0
                    initialized_regs[0] = true;
                    initialized_regs[1] = false;
                    initialized_regs[2] = false;
                    initialized_regs[3] = false;
                    initialized_regs[4] = false;
                    initialized_regs[5] = false;
                },
            }
        }

        if (!has_exit) return error.MissingExitInstruction;
    }

    /// Comptime verification function that evaluates program safety at compile time.
    pub fn comptimeVerify(comptime insns: []const Insn) void {
        comptime {
            verify(insns) catch |err| {
                @compileError("Corundum eBPF verification failed: " ++ @errorName(err));
            };
        }
    }
};
