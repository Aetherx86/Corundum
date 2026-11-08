# Corundum (컴파일 타임 검증 eBPF 바이트코드 어셈블러 & CFG 검증기)

[English](README.md) · [라이선스](LICENSE)

Corundum은 순수 Zig의 컴파일 타임 메타프로그래밍(`comptime`)을 통해 리눅스 eBPF / BPF 확장 명령어 시퀀스를 인코딩, 디스어셈블 및 정형 검증하는 도메인 특화 어셈블러이자 제어 흐름 안전성 검증기입니다.

## 아키텍처 개요

- **컴파일 타임 안전성 검증**: eBPF 레지스터 세트(R0~R10) 및 방향성 비순환 그래프(DAG) 불변식을 Zig 타입 시스템 내에 직접 모델링합니다. 순환 점프, 비정렬 64비트 메모리 로드, 미초기화 레지스터 읽기가 감지되면 바이너리 출력 전에 컴파일 에러를 발생시킵니다.
- **철저한 태그 유니언(Tagged Union)**: ALU, 분기, 메모리, 시스템 호출 명령어를 `union(enum)` 변형으로 정의하여 수학적 엄밀성과 불법 상태 전이 차단을 보장합니다.
- **제로 외부 의존성**: 독립 실행형 CLI 검증 바이너리와 C-ABI 공유 라이브러리(`libcorundum.so` / `libcorundum.dylib`)를 단일 빌드 스텝(`zig build`)으로 생성합니다.
- **적대적 DAG 방어**: 최대 명령어 길이를 제한하고 항상 전진하는 분기 불변식을 강제하여 무한 루프 공격을 사전에 방지합니다.

## 빌드 및 검증

```bash
# 컴파일 타임 정형 증명 단위 테스트 실행
zig build test

# 고속 릴리스 CLI 유틸리티 및 공유 라이브러리 빌드
zig build -Doptimize=ReleaseFast
```

## C-ABI 인터페이스

```c
int32_t corundum_verify_bytecode(const uint8_t* code_ptr, size_t code_len);
size_t corundum_disassemble_instruction(const uint8_t* inst_ptr, char* out_buf, size_t buf_cap);
```

## 라이선스

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
