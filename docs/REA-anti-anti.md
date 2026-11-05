# REA 대응 심층 분석 — 약점과 anti-anti 설계
> "REA는 이렇게 분석한다 → 그 분석은 이런 산출물에 의존한다(= 약점) → 그래서 우리는 그 산출물을 각 단계에서 고갈시키는 anti-anti를 만들었다."

본 문서는 `anti-reverse-shield`가 **왜 이렇게 설계됐는지**를 REA의 실제 동작 기준으로 설명합니다.
개념 설명은 [`guide.md`](guide.md), 각 방어의 한계는 [`WEAKNESSES.md`](WEAKNESSES.md)를 함께 보세요.

---

## TL;DR

REA는 **정적 추출 → 런타임 관찰 → AI 재구성**의 3단 파이프라인입니다. 각 단계는 특정 산출물에
의존합니다: symbols·strings·metadata·source map(정적), attach 가능한 프로세스·복호화된
트래픽(런타임), 그리고 그 둘을 재료로 한 evidence(AI 재구성). 결정적으로 REA는
**"각 결론의 evidence와 limitations를 함께 보고"** 합니다.

> **anti-anti의 목표 = REA 출력의 `limitations` 칸을 최대한 길게 만드는 것.**
> 산출물을 각 단계에서 굶기면, AI가 아무리 똑똑해도 추론할 재료가 없습니다.
> REA 출력 품질 = f(evidence quality). evidence를 열화시키면 REA가 열화됩니다.

---

## 0. REA 아키텍처 해부 (무엇을 상대하는가)

- **형태:** 단일 **MCP 서버** + AI 에이전트(Claude Code / Codex / Cursor / Gemini CLI / Grok) +
  외부 RE 툴 오케스트레이션. `npx rea-agents setup`으로 MCP 등록 + 워크플로우 지침 설치.
- **조사 루프:** 에이전트가 로컬 타깃 지정 → REA가 `inspect` + `trace` → findings(코드,
  references, **unknowns**) 반환 → 에이전트가 설명·구현·테스트. HAR을 AgentEnv/Docker
  환경으로 내보내 재현도 함.
- **두 축:**
  1. **정적 inspector** — 대부분의 바이너리/패키지 포맷. 타깃을 *실행하지 않고* 파일만 읽음.
  2. **런타임 capture** — "사용자 권한으로 타깃을 **실행하거나 상호작용**." 웹/프로세스/안드로이드/캡처.
- **핵심 성질:** evidence-based. **산출물이 없으면 결론도 없다.** 이게 REA의 구조적 약점이자 우리의 공략점.

---

## 1. REA가 각 타깃에서 노리는 "약점" (산출물 단위로 아주 자세히)

REA는 마법이 아니라, 아래 산출물을 긁어모읍니다. 각 항목이 곧 **우리가 없애야 할 대상**입니다.

### 1.1 네이티브 바이너리 — Hopper / Ghidra / IDA / Kuna (+ objdump, Rizin)
- **긁는 것:** pseudocode, assembly, **strings, symbols**, calls, references.
- **약점:** 심볼이 남으면 `verify_license`, `check_subscription` 같은 함수명이 그대로 노출 →
  AI가 즉시 의미 부여. 평문 문자열(URL, 에러 메시지, 키 포맷)은 동작의 지도. 표준 CFG는
  디컴파일러가 고수준 구조로 복원. imports/relocations로 어떤 API를 쓰는지 파악.

### 1.2 ELF 레이아웃 — pwntools
- **긁는 것:** sections, segments, **symbols, relocations**.
- **약점:** 동적 심볼 테이블·PLT로 외부 호출 목록이 그대로. 진입점·초기화 구조 노출.

### 1.3 언어별 built-in 정적 inspector — Go / Rust / IL2CPP / Godot PCK / BEAM / EVM / WASM 등
- **Go(최악):** `pclntab`·`moduledata`·타입 메타데이터·문자열 테이블 때문에 **함수명과 타입이
  거의 그대로 복원**. 컴파일 바이너리인데도 소스 구조가 보임.
- **Rust:** 심볼 demangle + panic 문자열(파일/라인 경로 포함)로 모듈 구조 유추.
- **IL2CPP:** `global-metadata.dat`가 있으면 Unity C# 메서드명·클래스 복원.
- **WASM(WABT), EVM:** 텍스트 포맷으로 변환되어 제어흐름이 드러남.

### 1.4 .NET 어셈블리 — metadata + CIL (정적만으로)
- **긁는 것:** 메타데이터 테이블, CIL 명령, 네이티브 의존성.
- **약점:** IL + 풍부한 메타데이터 = **거의 소스 수준 디컴파일**(dnSpy/ILSpy). 전 타깃 중 최약체.

### 1.5 JavaScript / Electron — 엔진 없이 정적만으로
- **긁는 것:** modules, imports, **source maps**, routes, IPC, native add-on 관계.
- **약점:** `app.asar` 풀면 **평문 JS 전부**. source map이 배포에 섞이면 원본 복원.
  라우트/IPC 채널이 그대로 보여 앱 구조가 통째로 노출. "정적만으로 충분"이 핵심 위험.

### 1.6 Android APK — headless JADX / `inspect_apk_signature` / Apktool
- **긁는 것:** manifest, classes, **디컴파일된 메서드**, 서명, 리소스 string table.
- **약점:** JADX가 읽기 쉬운 Java로 복원. 서명 정보·권한·컴포넌트 노출. 문자열 리소스가 힌트.

### 1.7 PyInstaller / Flutter
- **PyInstaller:** CArchive 멤버 + 추출된 bytecode → `.pyc` → 소스 복원.
- **Flutter:** Dart snapshot 해시·per-ABI digest로 버전/구성 식별.

### 1.8 런타임 / 캡처 (타깃을 실제로 돌려서 관찰)
- **웹:** Chrome 계열로 page structure, **scripts, network observations, screenshots**.
- **네트워크 캡처:** HAR / Fiddler SAZ, Linux에서 **mitmdump**(mitmproxy) → **평문 트래픽**.
  피닝이 없으면 API 구조·토큰·페이로드가 전부 노출.
- **패킷:** TShark / capinfos.
- **프로세스 행동:** native **PTY**로 터미널 출력·상호작용·종료·**파일시스템 관찰**.
- **Android 기기:** **adb**로 패키지·프로세스·로그·덤프·스크린샷·전송.
- **Linux 크래시:** pwntools + 선택적 **GDB/pwndbg**.
- **SQLite:** 테이블·인덱스·뷰·트리거·행 전체.

---

## 2. REA의 진짜 레버리지 — AI 자동화가 바꾸는 것 / 못 바꾸는 것

**바꾸는 것 (그래서 위험):**
- 속도: Ghidra/JADX 출력의 cross-reference를 사람 대신 수 분 안에 연결.
- 재구성: 저수준 디스어셈블 → 고수준 "이 함수는 라이선스를 검증한다" 서술로 승격.
- 숙련도 장벽 제거: RE 비전문가도 에이전트에게 시키면 됨.
- evidence 링크: 결론마다 근거 코드/참조를 붙여 신뢰도를 올림.

**못 바꾸는 것 (그래서 공략 가능):**
- **산출물 의존성은 그대로.** REA도 결국 Ghidra·JADX·dnSpy·mitmdump가 뱉은 것 **이상은 못 본다.**
- 재료가 없으면 AI는 빈손. 심볼이 없으면 `sub_4011A0`만 보이고, 트래픽이 암호화면 바이트 쓰레기만 본다.
- REA는 **limitations를 명시 보고**한다 → 우리가 산출물을 굶길수록 그 칸이 길어지고 결론은 "unknown"이 된다.

> **결론:** AI 자동화는 "분석을 빠르고 쉽게" 만들 뿐, "없는 정보를 만들어내지" 못한다.
> anti-anti는 바로 그 "없는 정보"를 의도적으로 만든다.

---

## 3. anti-anti 설계 — REA 파이프라인 **단계별 차단**

### Stage 1 — 정적 추출 고갈 (Starve the static inspectors)
REA의 1.1~1.7을 겨냥. 목표: 긁을 산출물 자체를 제거/변형.

| 없앨 산출물 | 방법 (본 툴킷) | 무력화되는 REA 분석기 |
|---|---|---|
| symbols | `strip --strip-all`, `-fvisibility=hidden`; Go `-ldflags "-s -w" -trimpath`; Rust `strip=true` | Hopper/Ghidra/IDA, pwntools, Go/Rust inspector |
| strings/constants | `ARS_OBF()` 컴파일타임 XOR (native/include/obfstr.hpp); garble `-literals` | strings 추출, 모든 디컴파일러의 상수 힌트 |
| 표준 CFG | OLLVM/o-mvll control-flow flattening, VMProtect | 디컴파일러의 구조 복원 |
| .NET IL/metadata | ConfuserEx `constants`+`ctrl flow`+`rename`+`anti ildasm`; **PublishAot**(IL 제거) | .NET inspector(1.4) |
| JS source maps / 평문 | source map 배포 금지, `javascript-obfuscator`, **bytenode(.jsc)** | JS/Electron inspector(1.5) |
| APK 가독 클래스 | R8 `repackageclasses ''` + 로그 제거, (상용) DexGuard 문자열 암호화 | JADX(1.6) |

### Stage 2 — 런타임 관찰 차단 (Blind the capture)
REA의 1.8을 겨냥. 목표: "실행해서 관찰"하는 경로를 교란/거부.

| 막을 캡처 | 방법 (본 툴킷) | 무력화되는 REA 캡처 |
|---|---|---|
| 디버거 attach | `ars_is_debugged()` — ptrace/TracerPid, sysctl P_TRACED, IsDebuggerPresent+PEB | GDB/pwndbg, Linux 크래시 분석 |
| 동적 instrumentation | `ars_frida_present()` — `/proc/self/maps` 스캔 (+ 네이티브 확장점) | Frida 기반 런타임 후킹 |
| 네트워크 가로채기 | Android `network_security_config.xml` 핀셋 + OkHttp `CertificatePinner` | **mitmdump/HAR 캡처(핵심)** → 평문 대신 거부 |
| node 덤프 | Electron fuses `RunAsNode:false`, `EnableNodeCliInspectArguments:false` | Electron 런타임 소스 덤프 |
| 변조된 상태 분석 | `ars_self_file_hash()` + (권장)in-memory `.text` 해시 | 패치 후 재배포/재실행 |

### Stage 3 — AI 재구성 열화 (Degrade the reconstruction)
Stage 1·2가 성공하면 자동으로 따라오는 효과 + 추가 장치.

- **unknowns 증가:** 심볼·문자열·CFG가 없으면 REA findings의 "unknown"이 급증, evidence가 비어 결론이 추측으로 전락.
- **간접 반응으로 행동 관찰 교란:** 탐지 시 즉시 종료하지 말 것(그러면 체크 지점을 알려줌).
  지연·상태 오염으로 PTY/프로세스 관찰에 **일관성 없는 신호**를 주입 → 재구성 난이도↑.
- **핵심 로직 서버 이전(최강):** REA가 볼 수 있는 건 네트워크 입출력뿐. 로직은 서버 너머라
  정적으로도 런타임으로도 재구성 불가. 클라이언트 체크 결과를 서버가 신뢰하지 않게 설계.

---

## 4. 종합 매핑 — REA 분석기 → 약점 → 우리 모듈 → REA의 재시도 → 잔여 강화

| REA 분석기 | 노리는 약점 | 우리 모듈/설정 | REA의 우회 재시도 | 잔여 강화 |
|---|---|---|---|---|
| Ghidra/IDA (native) | symbols·strings·CFG | strip + `ARS_OBF` + OLLVM | AI 디옵스큐에이션, 디컴파일 | VM 패커, 상수 분산 |
| pwntools (ELF) | symbols·relocations | strip, visibility hidden | 동적 심볼만으로 유추 | import 간접화(dlopen) |
| Go inspector | pclntab·type meta | `garble -literals -tiny`, `-trimpath` | garble 패턴 복원 연구 | 버전 갱신, 서버 로직 |
| .NET inspector | IL·metadata | ConfuserEx + **PublishAot** | de4dot 계열 언패커 | 네이티브 DLL 분리 |
| JS/Electron inspector | asar·source map·IPC | obfuscator + **bytenode** + source map 제거 | .jsc 디스어셈블, de4js | 핵심 로직 WASM/서버 |
| JADX (APK) | 디컴파일 클래스 | R8 repackage + 네이티브 분리 | smali 패치, Frida | 네이티브 JNI 체크 |
| mitmdump/HAR (network) | 미피닝 TLS | **cert pinning** (xml + OkHttp) | 루팅+universal unpinning | 페이로드 2차 암호화 + HMAC 서명 |
| GDB/pwndbg (crash/runtime) | attach 가능 | `ars_is_debugged()` 분산 | ScyllaHide, 체크 패치 | 다중 벡터 + in-memory 해시 |
| Frida (instrumentation) | 후킹 가능 | `ars_frida_present()` | gadget 리네임, maps 위조 | PLT/GOT 체크섬, libc 훅 탐지 |
| PTY/process 관찰 | 행동 노출 | 간접 반응 + 서버 종속 | 장시간 관찰 | 민감 동작을 서버로 |

---

## 5. 한계 — REA가 여전히 이기는 지점 (정직하게)

anti-anti는 **"REA를 불가능하게"가 아니라 "REA를 비싸고 불확실하게"** 만듭니다. 다음은 그대로 둡니다:
- **메모리 덤프:** 복호화된 문자열·키는 결국 메모리에 뜸 → 모든 정적 은닉 무력.
- **boolean 분기 패치:** 모든 탐지 체크는 한 줄 NOP으로 제거 가능.
- **루팅 기기 universal SSL unpinning:** Frida 스크립트 하나로 피닝 통째 무력화.
- **공개 디옵스큐에이터 + AI 디옵스큐에이션:** de4dot, OLLVM 디플래트너, de4js 등.

→ 그래서 **최종 방어선은 (1) 서버 측 로직/검증, (2) 경제성(크랙해도 이득 없게)** 입니다. 자세히는 [`WEAKNESSES.md`](WEAKNESSES.md).

---

## 6. REA 상대 배포 체크리스트

- [ ] 심볼·디버그 정보·source map·`.pdb`/`.dSYM`를 배포본에서 제거 → 정적 inspector 굶김
- [ ] 문자열/상수 암호화(`ARS_OBF`, garble `-literals`) → strings/상수 힌트 제거
- [ ] CFG 난독화(OLLVM) 또는 상용 패커 → 디컴파일 구조 복원 방해
- [ ] .NET은 PublishAot 또는 ConfuserEx(constants+ctrl flow) → IL 노출 최소화
- [ ] Electron: source map 제거 → obfuscate → **bytenode** → **fuses(RunAsNode off)**
- [ ] Android: R8 + 네이티브 JNI 체크 + **cert pinning(백업 핀 포함)**
- [ ] 안티 디버그/Frida 탐지를 **여러 지점에 분산**, 탐지 시 **지연·오염**(즉시 종료 금지)
- [ ] 자가 무결성 해시(디스크) + (권장) in-memory `.text` 해시
- [ ] **핵심 로직·검증·비밀을 서버로** → REA가 볼 수 있는 건 입출력뿐
- [ ] 네트워크 페이로드 2차 암호화 + HMAC 서명 → 피닝 뚫려도 본문 무의미
