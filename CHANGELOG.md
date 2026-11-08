# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 - 2026-11-08

### Added
- Initial release of Corundum comptime-verified eBPF bytecode assembler and CFG verifier.
- Exhaustive tagged unions (`union(enum)`) modeling ALU, memory, jump, and call operations.
- Comptime DAG validator enforcing forward branch progress, zero cycles, and memory alignment.
- Dual target build delivering native CLI and C-ABI shared library (`libcorundum`).
