# Phalanx: AI-Augmented Endpoint Detection & Response (EDR)

Windows ETW 커널 텔레메트리와 자율 AI 위협 헌팅 에이전트(Autonomous Hunter Agent)를 결합한 차세대 엔드포인트 탐지 및 대응(EDR) 솔루션입니다.

---

## 1. 기술 문서 (Documentation)

시스템 아키텍처, 커널 동시성 모델, AI ReAct 수사 설계, 성능 벤치마크 및 전체 개발 로드맵은 공식 지식베이스에 중앙 집중화되어 관리됩니다. 모든 상세 사양은 아래 **단일 진실 공급원(SSOT)** 문서를 참조하십시오.

* [00_project_overview.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/00_project_overview.md): 프로젝트 비전, 해결 과제, 3대 핵심 엔지니어링 가치 및 정량적 성능 지표
* [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md): C++20 네이티브 센서, 락-스왑 큐 동시성 모델, gRPC 통신 규약(`phalanx.proto`), WPF 4-View 관제 콘솔 토폴로지
* [02_ai_agent_investigation_design.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/02_ai_agent_investigation_design.md): Gemini ReAct 자율 수사관, 7대 OS 심층 포렌식 도구 규격, LiteDB 아카이브 및 Fail-Safe 동결 보존 파이프라인
* [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md): 단계별 기능 구현 마일스톤(Phase 1~5.5 완결), 아키텍처 불변식, 차기 활성 백로그(Phase 6) 및 기술 인수인계 사양서
* [04_performance_benchmarks.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/04_performance_benchmarks.md): 큐 동시성, 24μs 프로세스 동결, 0.354μs 룰 엔진, 카나리 누수 0 Bytes, 10대 엔터프라이즈 실무 스트레스 벤치마크(All-Green 10/10) 실측 레지스트리

---

## 2. 개발 환경 및 요구 사항 (Prerequisites)

본 프로젝트를 클론하여 빌드 및 테스트하기 위한 필수 환경입니다:

* **운영체제**: Windows 10 / 11 (x64)
* **실행 권한**: **관리자 권한(Run as Administrator) 필수** (Windows 커널 ETW 세션 구독, `NtSuspendProcess` 시스템 콜 호출 및 방화벽 규칙 조작에 필수)
* **.NET SDK**: [.NET 9.0 SDK 이상](https://dotnet.microsoft.com/download/dotnet) (.NET 10 호환, 프로젝트 타깃: `net9.0-windows`)
* **C++ 컴파일러**: Visual Studio 2026 (MSVC v14.51) 또는 Visual Studio 2022 (v17.x, "C++를 사용한 데스크톱 개발" 워크로드 필수)
* **빌드 시스템**: CMake (3.24 이상) 및 **Ninja** 빌드 도구 (시스템 PATH 환경변수 등록 필수)
* **패키지 관리자**: vcpkg (Manifest 모드 지원, 기본 위치: `%USERPROFILE%/vcpkg` 또는 `VCPKG_ROOT` 환경변수)

---

## 3. 빌드 및 테스트 가이드 (Build & Test Guide)

모든 작업은 **관리자 권한으로 실행된 PowerShell 콘솔**에서 리포지토리 루트 디렉터리를 기준으로 수행합니다:

### 3.1 프로젝트 빌드
* **C# 관제 솔루션 빌드**:
  ```powershell
  dotnet build Phalanx.sln -c Release
  ```
* **C++ 네이티브 센서 빌드** (Ninja 및 vcpkg 환경 필요):
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\build.ps1
  ```

### 3.2 테스트 및 품질 검증 (QA)
* **단위 테스트 (일상 QA, 85개 테스트 전원 통과, 약 1.0초 소요)**:
  ```powershell
  dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=Unit"
  ```
* **중립적 10대 엔터프라이즈 스트레스 벤치마크 (All-Green 10/10 무결점 검증)**:
  ```powershell
  dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=NeutralBenchmark"
  ```
* **풀체인 E2E 통합 시스템 검증 (C++ 센서 빌드 완료 후 실행)**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\run_fullchain_test.ps1
  ```
* **클라우드 AI 라이브 벤치마크 (실제 Vertex AI Gemini 3.7 Flash 호출, 약 3.5분 소요)**:
  ```powershell
  dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=Live" --logger "console;verbosity=normal"
  ```
> **주의**: `--filter "Category=Unit"`을 생략하고 `dotnet test`를 실행하면 클라우드 AI 10대 시나리오 실시간 추론 벤치마크(`Category=Live`)가 포함되어 약 3분 30초가 소요됩니다. 일상 개발 시에는 항상 `Category=Unit` 필터를 사용하십시오.

---

## 4. 솔루션 실행 가이드 (Quick Start & Run)

* **관제 콘솔(Cockpit GUI) 실행**:
  ```powershell
  dotnet run --project src/Phalanx.Cockpit/Phalanx.Cockpit.csproj -c Release
  ```
  *(또는 `src/Phalanx.Cockpit/bin/Release/net9.0-windows/Phalanx.Cockpit.exe` 직접 실행)*
* **C++ 센서 단독 구동 (관리자 권한)**:
  ```powershell
  .\out\build\windows-default\src\Phalanx.Sensor\Phalanx.Sensor.exe
  ```
* **모의 침해 시뮬레이터 구동**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\run_attack_simulator.ps1
  ```
* **LLM 인증 정보 및 오프라인 모드 안내**:
  - API 키가 없어도 **기본 23ms 오프라인 결정론적 FSM 엔진**으로 100% 자동 Fallback되어 10대 시나리오를 즉시 체험할 수 있습니다.
  - Gemini 클라우드 라이브 연동 시: 환경 변수 `GEMINI_API_KEY` 설정 또는 `src/Phalanx.Cockpit/Config/google-credentials.json`에 Google Cloud Service Account 키 배치 시 자동 활성화됩니다.
