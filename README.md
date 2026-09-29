# Phalanx: AI-Augmented Endpoint Detection & Response (EDR)

> **"결정론적 커널 센서와 자율 AI 위협 헌터의 유기적 결합"**

Phalanx(팔랑크스)는 초저지연 Windows ETW 커널 텔레메트리와 자율 AI 위협 헌팅 에이전트(Autonomous Hunter Agent)를 결합한 **차세대 엔드포인트 탐지 및 대응(EDR) 솔루션**입니다.

---

## 🏛️ 시스템 아키텍처 개요

```
[ C++20 Native Sensor ] (Kernel ETW + Double-Buffered Swap Queue)
         │  ▲
         │  │ gRPC Bidirectional Stream (Telemetry / MitigationCommand)
         ▼  │
[ C# Core Engine ] (LiteDB Threat Graph + Reflex Rule Engine + Gemini ReAct Agent)
         │
         ▼
[ C# WPF Cockpit ] (Live Node Graph + Threat Terminal + QuestPDF Report)
```

1. **Phalanx.Sensor (C++20)**:
   - `krabs-etw` 기반 `Kernel-Process/Network/Image` 마이크로초 단위 텔레메트리 수집
   - 무손실 락-스왑(Double-Buffered Lock-Swap) 버퍼링
   - Win32 `SuspendThread` (타깃 스레드 즉각 동결) 및 `TerminateProcess` 액추에이터
2. **Phalanx.Core (C# .NET)**:
   - gRPC 양방향 스트리밍 파이프라인
   - `LiteDB` 임베디드 인과 행위 그래프(Threat Graph) 및 부모-자식 트리 역추적
   - 0.05초(50ms) 이내 자동 차단을 수행하는 결정론적 1차 룰 엔진 (Reflex)
   - ReAct 기반 자율 AI 위협 헌팅 에이전트 및 5대 OS 조사 도구(Tool Calling)
3. **Phalanx.Cockpit (C# WPF / MVVM)**:
   - 침해 프로세스 인과 관계망 실시간 노드 그래프 렌더링
   - AI 에이전트의 사고(Thought)-행동(Action)-관찰(Observation) 스트리밍 피드
   - QuestPDF 기반 상용 등급 A4 포렌식 침해사고 리포트 원클릭 출력

---

## 📚 상세 지식베이스 및 아키텍처 사양서

본 프로젝트의 상세 사양 및 설계 문서는 `Obsidian.Agent` 지식베이스를 단일 진실 공급원(SSOT)으로 참조합니다:

- [Phalanx Knowledge Base Index](../Obsidian.Agent/Phalanx/README.md)
- [00_project_overview.md](../Obsidian.Agent/Phalanx/docs/00_project_overview.md): 비전 및 3대 엔지니어링 가치
- [01_system_architecture.md](../Obsidian.Agent/Phalanx/docs/01_system_architecture.md): 시스템 토폴로지 및 파이프라인 명세
- [02_ai_agent_investigation_design.md](../Obsidian.Agent/Phalanx/docs/02_ai_agent_investigation_design.md): ReAct 위협 헌터 및 도구 호출 설계
- [03_implementation_roadmap.md](../Obsidian.Agent/Phalanx/docs/03_implementation_roadmap.md): 단계별(Phase 1~4) 구현 로드맵 및 DoD
