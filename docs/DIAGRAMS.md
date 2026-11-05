# 메커니즘 다이어그램 (ASCII) — 원리를 그림으로

> 글자 그림으로 각 방어가 "무엇을, 어느 순간, 어떻게" 막는지 보여줍니다.
> 코드 레벨 설명은 [`PRINCIPLES.md`](PRINCIPLES.md), 한계는 [`WEAKNESSES.md`](WEAKNESSES.md).

---

## 0. 큰 그림 — 공격 파이프라인 vs 4계층 방어

REA 류 도구는 "정적 추출 → 동적 관찰 → AI 재구성"으로 움직이고, 각 단계는 특정
산출물(evidence)에 의존합니다. 방어는 그 산출물을 단계마다 고갈시킵니다.

```
      ATTACKER  (REA + 하부 툴)                 DEFENSE  (anti-reverse-shield)
      ==========================               ==============================

      [ Ghidra / IDA / JADX ] ---- static ----> L1  strip · ARS_OBF · OLLVM
                                                     (심볼/문자열/CFG 제거)
      [ Frida / gdb / pwndbg ] --- dynamic ---> L2  anti-debug · anti-hook · timing
                                                     (attach/후킹 교란)
      [ mitmproxy / tshark ] ----- network ---> L4  cert pinning · payload crypto
             |                                       (평문 -> 쓰레기)
             |                                  L3  integrity · indirect reaction
             v                                       (패치 탐지 · 간접 반응)
      [ AI reconstruction ] <----- evidence ---------+
             |                     (산출물이 마르면 재구성 불가)
             v
      findings { code, refs, UNKNOWN, limitations }   <= 목표: UNKNOWN/limitations 최대화
```

---

## 1. 인라인 훅 (detour) — `ars_hooks_present()`

Frida 같은 도구는 함수 **프롤로그**를 점프 명령으로 덮어써서 가로챕니다. 우리는 핫한
libc 함수의 첫 바이트가 점프 계열 opcode인지 검사해 그 흔적을 봅니다.

```
   BEFORE (clean `open`)              AFTER (hooked)
   ---------------------              --------------------------------------
   open+0:  F3 0F 1E FA  endbr64      open+0:  E9 7B 3C 11 00   jmp   detour   <-- 탐지!
   open+4:  55           push rbp              (원래 명령은 trampoline으로 이동)
   open+5:  48 89 E5     mov rbp,rsp
            ...                        detour:  <attacker code>
                                                ... ; jmp open+5   (원함수로 복귀)

   검사: endbr64(F3 0F 1E FA)는 건너뛰고, 그 다음 바이트가
         E9 / FF25 / FFE0 / push+ret / mov rax,imm64;jmp rax 이면 훅으로 판정.
```

---

## 2. 안티 디버그 — `ars_is_debugged()` 결정 흐름

```
   ars_is_debugged()
        |
        v
   /proc/self/status 의 TracerPid 읽기
        |
     == 0 ? --------- no ---------> [ DEBUGGER ]  (gdb/strace/pwndbg가 붙음)
        | yes
        v
   ptrace(PTRACE_TRACEME) == -1 ? -- yes --> [ DEBUGGER ]  (이미 누군가 trace 중)
        | no
        v
   ptrace(PTRACE_DETACH);  ---> [ clean ]

   * TracerPid 읽기를 먼저 하는 이유: 프로세스 상태를 건드리지 않는 순수 read라,
     ptrace 프로브(상태 변화)보다 안전하고 조용하다.
```

---

## 3. 무결성 — 디스크 해시 vs 메모리 해시 (서로 다른 걸 잡는다)

```
                     on-disk file           in-memory .text (RAM)
                     ------------           ---------------------
   clean             [ 90 1A 7C .. ]        [ 90 1A 7C .. ]
   cracked.exe 배포  [ EB 1A 7C .. ]  <--    [ EB 1A 7C .. ]     파일이 다름
   런타임 패치(gdb)  [ 90 1A 7C .. ] 파일OK  [ EB 1A 7C .. ]  <-- RAM만 다름

   ars_self_file_hash()  => 잡음: 배포된 cracked.exe   (디스크 불일치)
   ars_text_hash()       => 잡음: 실행 중 메모리 패치  (파일은 멀쩡, RAM 불일치)

   둘 다 필요: 하나만 쓰면 반대 케이스를 놓친다.
```

---

## 4. 인증서 피닝 — MITM 프록시(mitmproxy)를 끊는 지점

```
   client ===ClientHello===>  [ mitmproxy ]  ===>  real server
   client <==FAKE cert=======  CA = mitm 가짜
      |
      | 1) 체인 검증은 통과 (기기에 mitm CA가 설치돼 있으면)
      v
   2) SPKI(서버 공개키) 해시 == 앱에 박힌 pin ?
      |                               |
     NO                              YES (공격자가 pin까지 바꿔치기한 경우만)
      |                               |
      v                               v
   [ ABORT ]  캡처 결과 = TLS 에러      [ 통과 ]
   = 평문이 아니라 쓰레기만 남음

   그래서 루팅+universal unpinning에 대비해 페이로드 2차 암호화 + HMAC를 겹친다.
```

---

## 5. 제어흐름 평탄화 (control-flow flattening) — 디컴파일러의 구조 복원 파괴

```
   ORIGINAL (읽기 쉬움)            FLATTENED (디스패처 수프)
   --------------------            -------------------------------
      A                            state = 0
      if (c) B else C              while (1) switch (state) {
      D                              case 0: A; state = c ? 1 : 2; break;
                                     case 1: B; state = 3;         break;
   디컴파일 결과:                    case 2: C; state = 3;         break;
      명확한 if/else/흐름             case 3: D; return;
                                   }
                                 디컴파일 결과: 거대한 switch 하나,
                                 원래의 if/else 구조는 사라짐
```

---

## 6. 컴파일타임 문자열 암호화 — 평문이 "존재하는 창"을 좁힌다

```
   binary .rodata:   [ 32 1B 0F 55 .. ]   <- XOR된 바이트. `strings`는 쓰레기만 봄
         |
         |  사용 시점에 decrypt(buf)
         v
   stack buffer:     [ 'h' 't' 't' 'p' .. ]  <- 평문이 RAM에 "존재"  <== 메모리 덤프는 이걸 봄
         |
         |  memset(buf, 0, n)
         v
   stack buffer:     [ 00 00 00 00 .. ]      <- 평문 창 닫힘

   결론: 정적(strings/디컴파일)은 막지만 런타임 덤프는 못 막는다.
         decrypt -> 사용 -> 즉시 wipe 로 창을 최소화하는 게 핵심.
```

---

## 7. 증거 고갈 깔때기 — 왜 REA가 "UNKNOWN"을 뱉게 되는가

```
   방어를 겹칠수록 REA가 볼 수 있는 evidence가 줄어든다:

   (무방비)        REA: "verify_license() 가 서버에 POST 한다" (확신)
   + strip         REA: "sub_4011A0() 가 뭔가 한다"            (이름 소실)
   + 문자열 암호화  REA: "상수 불명, 용도 추정"                  (힌트 소실)
   + CFF 난독화     REA: "디스패처 루프, 로직 불명"              (구조 소실)
   + 피닝/암호화    REA: "암호문만 관측됨"                       (행동 소실)
   + 서버 로직      REA: "입력/출력만 보임" -> findings = 대부분 UNKNOWN

   REA는 각 결론에 evidence와 limitations를 함께 보고한다.
   방어의 성공 = limitations 칸이 길어지고 결론이 추측으로 전락하는 것.
```

---

## 8. 간접 반응 — `ars_react()` 타임라인 (즉시 종료 금지)

```
   t0      [탐지]  디버거/훅 발견        <-- 여기서 exit() 하면 체크 위치를 알려주는 꼴
   t0+δ    ars_react(v): sleep(50~113ms, 지터)
   t0+δ    return v ^ 0xA5A5A5A5         <-- 값을 살짝 오염
   ...     (수백 개 명령 뒤, 멀리 떨어진 곳에서)
   tN      [결과] 엉뚱한 값 / 지연된 크래시  <-- 분석가는 "버그"처럼 보이는 실패만 목격

   공격자는 "체크 한 줄"이 아니라 "의미 전체"를 이해해야 하므로 비용이 급증한다.
```
