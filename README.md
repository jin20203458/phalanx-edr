# Phalanx: AI-Augmented Endpoint Detection & Response (EDR)

Phalanx는 Windows ETW 커널 텔레메트리와 자율 AI 위협 헌팅 에이전트(Autonomous Hunter Agent)를 결합한 차세대 엔드포인트 탐지 및 대응(EDR) 솔루션입니다.

## 기술 문서 (Documentation)

프로젝트 전체 시스템 아키텍처, 에이전트 인지 모델 및 향후 개발 로드맵은 `Obsidian.Agent` 저장소에 중앙 집중화되어 관리됩니다. 아래 문서들은 개발자와 코딩 에이전트 모두가 참조하는 **단일 진실의 원천(Single Source of Truth)**입니다.

- [00_project_overview.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/00_project_overview.md): 비전, 해결 과제 및 3대 핵심 엔지니어링 가치
- [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md): C++ 센서, gRPC 양방향 스트리밍 및 WPF 관제 콘솔 토폴로지
- [02_ai_agent_investigation_design.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/02_ai_agent_investigation_design.md): ReAct 위협 헌터 에이전트, 5대 OS 도구 및 Threat Graph 메모리 설계
- [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md): 단계별 구현 마일스톤, 완료 정의(DoD), 통합 기술 인수인계 및 활성 백로그 사양서 (통합 SSOT)
- [04_performance_benchmarks.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/04_performance_benchmarks.md): EDR 시스템 전체 실측 벤치마크 및 성능 프로파일링 통합 레지스트리

> **참고**: 전체 시스템 구성도 및 흐름도는 중복을 방지하기 위해 [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md)에서 제공합니다.

## 주요 기능 (Key Features)

- **결정론적 초저지연 커널 텔레메트리**: Windows ETW를 유저모드 C++20으로 후킹하여 프로세스 트리, 네트워크 소켓, 모듈 로드 이벤트를 수집하고, 더블 버퍼드 락-스왑(Double-Buffered Lock-Swap) 큐를 통해 락 경합 없이 유실률 0%를 보장합니다.
- **반사신경 위협 동결 (Reflex Freeze)**: 비정상 프로세스 체인 감지 시 `ntdll!NtSuspendProcess`를 직접 호출하여 타깃 프로세스를 **24μs** 만에 원자적으로 동결(Toolhelp32 스레드 순회 안전 폴백 2중 방어선)하며, 데드락 방지용 세이프티 워치독(기본 10초, LLM 수사 시 1회 한정 +50초 연장 티켓)으로 보호됩니다.
- **인과 행위 그래프 (Threat Graph Memory)**: C++ 메모리 DAG 및 C# `LiteDB` 기반의 임베디드 데이터 구조로 프로세스 부모-자식 족보와 행위 이력을 보존하여 침해 진입점(Initial Access)을 O(1) 수준으로 즉각 역추적합니다.
- **자율 AI 위협 헌터 (Autonomous Hunter Agent)**: Gemini 3.7 Flash 모델 기반 ReAct 추론 루프로 5대 OS 도구(명령행 디코더, VAD 가상 메모리 스캐너, 위협 평판 조회, MITRE ATT&CK 매핑, 윈도우 방화벽 격리)를 자율 호출하며 가설을 검증합니다.
- **실시간 생동감 수사 UX & 엔터프라이즈 테마**: 3계층 실시간 UX 파이프라인(사건 카드 Glow 호흡 펄스, Turn별 실시간 상태 텍스트, ReAct 턴 스트리밍 증식 및 자동 펼침, 100ms 정밀 수사 타이머) 및 무깜빡임 다크/라이트/시스템 동적 테마(`ThemeManager`, Windows DWM 네이티브 타이틀바 동기화)를 지원합니다.
- **모의 침해 텔레메트리 랩 (Attack Lab)**: 고난도 회피 공격 및 정상 관리 작업을 포함한 10대 실무 시나리오(Office C2, 랜섬웨어 vssadmin 삭제, CertUtil, HTA, 위장 드로퍼, SCCM 점검, 개발 도구 루프백, LOLBAS Rundll32, VAD 인젝션) 및 동적 커스텀 공작소(#99)를 3-모드(CleanRoom, OsHybrid, LiveExpert)로 실측 검증합니다.
- **업계 표준 텔레메트리 게이지 바**: 하단 상태 바를 현재 활성 상태 유지 수(Gauge) 모델(`FROZEN`, `RESTORED`, `TERMINATED`, `MONITORED`)로 일원화하여 프로세스 생명주기 및 종료 이벤트를 무결하게 추적합니다.

## 개발 환경 및 시작 가이드 (Developer Guide)

### 요구 사항 (Prerequisites)
* Windows 10/11 (x64)
* Visual Studio 2026 (Dev18 / MSVC v14.51) 또는 Visual Studio 2022 (v17.x)
* [.NET 10.0 / 8.0 SDK](https://dotnet.microsoft.com/download/dotnet) (.NET 9.0 호환)
* CMake (3.24 이상) 및 vcpkg (Manifest 모드 지원)

### 구현 및 빌드 로드맵
본 프로젝트는 [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md)에 명시된 마일스톤에 따라 순차적으로 구축됩니다:
1. **Phase 1 ~ 3.5 [완료]**: C++20 커널 센서(24μs 원자적 동결, 100μs 로컬 룰 엔진, 0.1ms 현장 사살), gRPC 스트리밍, C# 자율 AI 위협 헌터(ReAct 루프, 5대 OS 도구), 풀체인 폐루프 E2E 실증(555ms).
2. **Phase 4 ~ 4.2 [완료]**: 엔터프라이즈 4-View 관제 콕핏(Incidents, Process Graph, Investigation Studio, Attack Lab), 센서 UAC 자동 기동, 실시간 동적 테마(Dark/Light/System), 3계층 AI 실시간 수사 생동감 UX 파이프라인, 게이지(Gauge) 텔레메트리 바.
3. **Phase 5.2 [완료]**: 어택랩 10대 실무 시나리오 체제 개편 및 가상 VAD 메모리 스캔 엔진 연동, FSM 루프백 오탐 방지 및 인메모리 인젝션 독립 50점 가산.
4. **Phase 5 [진행 중 - 활성 백로그]**:
   - **[1순위] `FileInspectionTool.cs` 구현**: WinVerifyTrust 서명 검증, 시스템 경로 위장(T1036.005) 적발, 섀넌 엔트로피 연산 (수사 시간 36.5초 ➔ 10초 내외로 72% 압축).
   - **[2순위] `QuestPDF` 기반 A4 포렌식 리포트 엔진**: LiteDB 포렌식 아카이브 기반 상용 공공/금융 보안 표준 양식 1장 요약 A4 PDF 문서 자동 생성.
   - **[3순위] MITRE ATT&CK 내비게이터 뷰**: 12대 공격 전술 매트릭스 미니맵 연동.

### 빌드 및 테스트 가이드 (Build & Test Guide)
* **C# 빌드**:
  ```powershell
  dotnet build Phalanx.sln -c Release
  ```
* **C++ 센서 빌드**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\build.ps1
  ```
* **단위 테스트 (일상 QA, 49개 테스트 전원 통과, 약 1.0초 소요)**:
  ```powershell
  dotnet test tests/Phalanx.Agent.Tests/ -c Release --no-build --filter "Category=Unit"
  ```
* **클라우드 AI 벤치마크 테스트 (실제 Vertex AI Gemini 3.7 Flash 호출, 약 3.5분 소요)**:
  ```powershell
  dotnet test tests/Phalanx.Agent.Tests/ -c Release --no-build --filter "Category=Live" --logger "console;verbosity=normal"
  ```
* **풀체인 통합 검증**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\run_fullchain_test.ps1
  ```
> **주의**: `--filter "Category=Unit"`을 생략하고 `dotnet test`를 실행하면 클라우드 AI 10대 시나리오 실시간 추론 벤치마크(`Category=Live`)가 포함되어 약 3분 30초가 소요됩니다. 일상 개발 시에는 항상 `Category=Unit` 필터를 사용하십시오.

## 참조 로컬 코드 자산 (Reference Code Assets)
구현 시 기존 검증된 로컬 프로젝트의 아키텍처 패턴 및 UI 디자인 토큰만을 학습·참조합니다 (Clean-Room 방식):
- **C++ 락-스왑 큐 & 비동기 gRPC (Pattern Only)**: `../MundusVivens.GameServer.Cpp` (`AsyncGrpcClient.cpp`)
- **C# gRPC 수신 & LiteDB 캐시 (Pattern Only)**: `../MundusVivens`
- **AI 스트리밍 사고/서사 텍스트 (Tokens Only)**: `../GRC` (`Themes/ModernStyles.xaml`)
- **엔터프라이즈 대시보드 & 캡슐 버튼 (Tokens Only)**: `../../../../clang-lab/UI_WPF/ArqaStatic` (`Themes/DarkTheme.xaml`)

