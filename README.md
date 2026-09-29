# Phalanx: AI-Augmented Endpoint Detection & Response (EDR)

Phalanx는 Windows ETW 커널 텔레메트리와 자율 AI 위협 헌팅 에이전트(Autonomous Hunter Agent)를 결합한 차세대 엔드포인트 탐지 및 대응(EDR) 솔루션입니다.

## 기술 문서 (Documentation)

프로젝트 전체 시스템 아키텍처, 에이전트 인지 모델 및 향후 개발 로드맵은 `Obsidian.Agent` 저장소에 중앙 집중화되어 관리됩니다. 아래 문서들은 개발자와 코딩 에이전트 모두가 참조하는 **단일 진실의 원천(Single Source of Truth)**입니다.

- [00_project_overview.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/00_project_overview.md): 비전, 해결 과제 및 3대 핵심 엔지니어링 가치
- [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md): C++ 센서, gRPC 양방향 스트리밍 및 WPF 관제 콘솔 토폴로지
- [02_ai_agent_investigation_design.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/02_ai_agent_investigation_design.md): ReAct 위협 헌터 에이전트, 5대 OS 도구 및 Threat Graph 메모리 설계
- [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md): 단계별(Phase 1~4) 구현 마일스톤 및 완료 정의(DoD)

> **참고**: 전체 시스템 구성도 및 흐름도는 중복을 방지하기 위해 [01_system_architecture.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/01_system_architecture.md)에서 제공합니다.

## 주요 기능 (Key Features)

- **결정론적 초저지연 커널 텔레메트리**: Windows ETW를 유저모드 C++20으로 후킹하여 프로세스 트리, 네트워크 소켓, 모듈 로드 이벤트를 수집하고, 더블 버퍼드 락-스왑(Double-Buffered Lock-Swap) 큐를 통해 락 경합 없이 유실률 0%를 보장합니다.
- **반사신경 위협 동결 (Reflex Freeze)**: 비정상 프로세스 체인 감지 시 Win32 `SuspendThread`를 직접 호출하여 타깃 프로세스를 20ms 이내에 즉각 동결합니다.
- **인과 행위 그래프 (Threat Graph Memory)**: `LiteDB` 기반의 임베디드 DAG 구조로 프로세스 부모-자식 관계와 행위 이력을 보존하여 침해 진입점(Initial Access)을 O(h)로 역추적합니다.
- **자율 AI 위협 헌터 (Autonomous Hunter Agent)**: Gemini 모델 기반 ReAct 추론 루프로 5대 OS 도구(명령행 디코더, YARA/메모리 스캐너, 평판 조회, MITRE TTP 매핑, 방화벽 IP 차단)를 자율 호출하며 가설을 검증합니다.
- **WPF 관제 콕핏 & 포렌식 리포트**: 실시간 침해 노드 그래프와 AI 사고 스트리밍 터미널을 제공하며, QuestPDF를 통해 상용 등급의 A4 포렌식 침해사고 분석 리포트를 1초 이내에 출력합니다.

## 개발 환경 및 시작 가이드 (Developer Guide)

### 요구 사항 (Prerequisites)
* Windows 10/11 (x64)
* Visual Studio 2022 (C++ 데스크톱 개발 워크로드 및 .NET 데스크톱 개발 워크로드)
* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) 이상
* CMake (3.24 이상) 및 vcpkg

### 구현 및 빌드 로드맵
본 프로젝트는 [03_implementation_roadmap.md](https://github.com/jin20203458/Obsidian.Agent/blob/main/Phalanx/docs/03_implementation_roadmap.md)에 명시된 4단계 마일스톤에 따라 순차적으로 구축됩니다:
1. **Phase 1 (Sensor & IPC)**: C++20 ETW 수집기 및 gRPC 양방향 통신 파이프라인
2. **Phase 2 (Core & Reflex)**: C# LiteDB 인과 그래프 및 50ms 결정론적 1차 룰 엔진
3. **Phase 3 (AI Agent & Tools)**: ReAct 추론 루프 및 5대 OS 조사 도구 체계
4. **Phase 4 (Cockpit & Presentation)**: WPF 노드 그래프 UI 및 QuestPDF 리포트

## 참조 로컬 코드 자산 (Reference Code Assets)
구현 시 기존 검증된 로컬 프로젝트의 패턴을 직접 참조합니다:
- **C++ 락-스왑 큐 & 비동기 gRPC**: `../MundusVivens.GameServer.Cpp` (`AsyncGrpcClient.cpp`)
- **C# gRPC 수신 & LiteDB 캐시**: `../MundusVivens`
- **AI 스트리밍 사고/서사 텍스트**: `../GRC` (`Themes/ModernStyles.xaml`)
- **엔터프라이즈 대시보드 & 캡슐 버튼**: `../../../../clang-lab/UI_WPF/ArqaStatic` (`Themes/DarkTheme.xaml`)

