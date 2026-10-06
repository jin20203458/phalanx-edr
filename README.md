# Phalanx: AI-Augmented Endpoint Detection & Response (EDR)

Windows ETW 커널 텔레메트리(C++20)와 Gemini ReAct 자율 위협 수사관(C#)을 결합한 차세대 엔드포인트 탐지 및 대응(EDR) 솔루션입니다. 비인가 프로세스 행위 감지 즉시 **24μs 선제 프로세스 동결(`NtSuspendProcess`)**을 집행하고, AI 수사관이 7대 OS 포렌식 도구를 자율 호출하여 원인 규명 및 침해사고 리포트 작성을 자동 완결합니다.

---

## 1. 솔루션 시각 자료 (Visual Showcase)

| 엔터프라이즈 관제 대시보드 | 모의 침해 시뮬레이터 (어택랩) |
| :---: | :---: |
| ![메인 대시보드](docs/images/dashboard_dark.png) | ![어택랩 시뮬레이터](docs/images/attack_lab.png) |
| *실시간 프로세스 상태, 선제 격리 현황 및 위협 타임라인* | *5대 실전 공격 시나리오(LOLBins, C2 통신 등) 원클릭 실증* |

| ReAct 자율 수사 로그 (심층 수사실) | 종합 포렌식 리포트 (사후 감사용) |
| :---: | :---: |
| ![ReAct 수사 로그](docs/images/react_investigation.png) | ![포렌식 리포트](docs/images/forensic_report.png) |
| *Thought → Action → Observation 자율 추론 및 도구 호출* | *위협 인덱스, MITRE ATT&CK 기법, IoC 디지털 증거 보존* |

| 실시간 프로세스 트리 (DAG 분석) | C++20 네이티브 커널 센서 |
| :---: | :---: |
| ![프로세스 트리](docs/images/process_tree.png) | ![C++ 센서 콘솔](docs/images/sensor_terminal.png) |
| *부모-자식 계통도 추적 및 비인가 은닉 실행 감지* | *ETW 무손실 수집 및 24μs 초저지연 NtSuspendProcess* |

---

## 2. 공식 기술 문서 (SSOT Documentation)

시스템 아키텍처, 커널 동시성 모델, ReAct 수사 설계 및 상세 벤치마크는 공식 지식베이스를 참조하십시오:

* [00_project_overview.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/00_project_overview.md): 프로젝트 비전, 3대 핵심 엔지니어링 가치 및 정량적 성능 지표
* [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md): C++20 네이티브 센서, 락-스왑 큐 동시성 모델, gRPC 통신 규약(`phalanx.proto`), WPF 4-View 관제 콘솔
* [02_ai_agent_investigation_design.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/02_ai_agent_investigation_design.md): Gemini ReAct 자율 수사관, 7대 OS 심층 포렌식 도구 규격, LiteDB 아카이브 파이프라인
* [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md): 단계별 기능 구현 마일스톤(Phase 1~5.5 완결), 아키텍처 불변식 및 차기 백로그(Phase 6)
* [04_performance_benchmarks.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/04_performance_benchmarks.md): 24μs 프로세스 동결, 0.354μs 룰 엔진, 카나리 누수 0 Bytes, 10대 실무 스트레스 벤치마크 실측치
* [05_csharp_architecture_modernization_plan.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/05_csharp_architecture_modernization_plan.md): C# 관제 솔루션 구조적 혁신(CQRS 캡슐화, 테스트 스위트 최신화) 마스터 플랜

---

## 3. 개발 환경 및 요구 사항 (Prerequisites)

* **운영체제**: Windows 10 / 11 (x64)
* **실행 권한**: **관리자 권한(Run as Administrator) 필수** (Windows 커널 ETW 세션 구독, `NtSuspendProcess` 호출)
* **.NET SDK**: [.NET 9.0 SDK 이상](https://dotnet.microsoft.com/download/dotnet) (.NET 10 호환, 프로젝트 타깃: `net9.0-windows`)
* **C++ 컴파일 환경** *(센서 소스 컴파일 시에만 필요)*:
  * Visual Studio 2022 / 2026 (MSVC v14.3x 이상, "C++를 사용한 데스크톱 개발" 워크로드)
  * CMake 3.24 이상 및 Ninja 빌드 도구 (시스템 PATH 환경변수 등록 필수)
  * vcpkg (Manifest 모드, `-DCMAKE_TOOLCHAIN_FILE` 또는 `VCPKG_ROOT` 환경변수)

---

## 4. 빌드 및 테스트 가이드 (Build & QA Guide)

모든 작업은 **관리자 권한으로 실행된 PowerShell 콘솔**에서 수행합니다:

### 4.1 프로젝트 빌드
```powershell
# C# 관제 솔루션 빌드
dotnet build Phalanx.sln -c Release

# C++ 네이티브 센서 빌드 (Ninja 및 vcpkg 환경 필요)
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

### 4.2 테스트 및 품질 검증 (QA)
```powershell
# [Fast QA] 170개 단위 테스트 전원 통과 (약 1.0초 소요, All Green)
dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=Unit"

# [스트레스 벤치마크] 중립적 10대 엔터프라이즈 실무 시나리오 무결점 검증 (10/10 PASS)
dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=NeutralBenchmark"

# [풀체인 E2E] C++ 센서 -> gRPC -> AI 에이전트 전 구간 통합 검증
powershell -ExecutionPolicy Bypass -File .\scripts\run_fullchain_test.ps1

# [클라우드 라이브] 실제 Gemini 3.7 Flash 실시간 멀티턴 추론 벤치마크 (~3.5분 소요)
dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=Live" --logger "console;verbosity=normal"
```

> **참고**: `--filter "Category=Unit"`을 생략하고 `dotnet test`를 실행하면 클라우드 AI 10대 시나리오 실시간 추론 벤치마크(`Category=Live`)가 포함되어 약 3분 30초가 소요됩니다. 일상 개발 시에는 항상 `Category=Unit` 필터를 사용하십시오.

---

## 5. 솔루션 실행 및 시연 가이드 (Quick Start & Run)

### 5.1 관제 콘솔(Cockpit GUI) 실행
```powershell
dotnet run --project src/Phalanx.Cockpit/Phalanx.Cockpit.csproj -c Release
```
*(또는 컴파일된 실행 파일 `src\Phalanx.Cockpit\bin\Release\net9.0-windows\Phalanx.Cockpit.exe` 직접 실행)*

### 5.2 모의 침해 시뮬레이터 구동 (어택랩 실증)
* **방법 1 (GUI 원클릭)**: 관제 콘솔 좌측 네비게이션 하단 **[어택랩]** 아이콘 클릭 ➔ 5대 공격 시나리오(Office 매크로 파일리스 침투 등) 선택 ➔ **[모의 침해 주입 ▶]** 클릭
* **방법 2 (스크립트)**:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\run_attack_simulator.ps1
  ```
* **C++ 센서 단독 구동 (관리자 권한)**:
  ```powershell
  .\out\build\windows-default\src\Phalanx.Sensor\Phalanx.Sensor.exe
  ```

### 5.3 핵심 동작 검증 포인트
1. **24μs 선제 동결**: 악성 의심 프로세스 기동 즉시 `NtSuspendProcess` 시스템 콜로 일시 정지 (`SUSPENDED` 상태 시각화)
2. **ReAct AI 심층 포렌식**: 심층 수사실 탭에서 Thought -> Action -> Observation 루프를 거치며 7대 OS 도구로 은닉 위협 규명
3. **자동 조치 및 리포트**: 악성 판정 시 `ACTION_KILL` 단행 및 `IncidentReports` 폴더 내 종합 포렌식 리포트 자동 생성

---

## 6. LLM API 설정 안내 (오프라인 모드 vs Gemini 클라우드 모드)

* **[기본값: 오프라인 결정론적 ReAct 모드 (API 키 불필요)]**
  * 별도 API Key를 설정하지 않아도 내장된 **23ms 로컬 ReAct Fallback 엔진**이 자동 작동합니다.
  * 외부 네트워크 통신 없이 24μs 프로세스 동결, 5대 침해 시나리오 탐지(100%), 7대 OS 포렌식 도구 호출, 리포트 생성 등 전 기능을 즉시 시연 및 검증할 수 있습니다 (`LOCAL FALLBACK` 배너 표시).
* **[선택 사항: Google Gemini 클라우드 라이브 연동 모드]**
  * **GUI 설정**: 관제 콘솔 좌측 네비게이션 하단 **[설정]** 아이콘 클릭 ➔ Google AI Studio API Key 입력 후 저장 (`CLOUD LLM` 활성화).
  * **설정 파일**: 실행 폴더 내 `AppSettings.json`의 `"ApiKey"` 필드에 키 입력 (`"UseVertexAI": false`).
  * *(Google Cloud Vertex AI 사용 시: `Config/google-credentials.json` 배치 후 `"UseVertexAI": true`)*
