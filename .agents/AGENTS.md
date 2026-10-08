<project_philosophy>
Focus: Deterministic low-overhead ETW telemetry, zero-loss lock-swap queues, atomic NtSuspendProcess, gRPC streaming, LiteDB threat DAG, and tool-augmented ReAct.
</project_philosophy>

<engineering_rules>
- **Kernel & Memory**: Manage Win32 handles with RAII (`HANDLE`, `HMODULE`, `SC_HANDLE`). Use smart pointers for telemetry buffers. Keep ETW callback threads non-blocking via lock-swap queues.
- **Process Actuation**: Freeze suspects via `NtSuspendProcess` guarded by `SafetyWatchdog`. Keep `LocalRuleEngine` reflex rules strictly sub-millisecond.
- **Async & Concurrency**: Use `async`/`await` end-to-end; NEVER block synchronously (`.Result`, `.Wait()`, `.GetAwaiter().GetResult()`). Maintain LiteDB concurrency safety.
- **Decision Authority (SSOT)**: ReAct agent verdict is SSOT over heuristic overrides. Maintain 23ms offline deterministic fallback when cloud LLM is unavailable; restrict Fail-Secure strictly to watchdog timeouts or disabled fallback.
- **Forensic Tools**: Centralize simulation mock data in `CleanRoomSimulationStore`; never hardcode test data inside production tools.
- **Cockpit UI & Headless**: Follow strict MVVM via `CommunityToolkit.Mvvm`. Marshal background updates through `CockpitUiBridge.Instance`. Support headless execution where `Application.Current` is null. Zero decorative emojis.
</engineering_rules>

<critical_rules>
- **Build**: `dotnet build Phalanx.sln` (C#), `powershell -ExecutionPolicy Bypass -File .\build.ps1` (C++)
- **Test**:
  - Unit (Fast QA, 170 tests, ~2.0s): `dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=Unit"`
  - Stress (10 scenarios, ~0.5s): `dotnet test tests/Phalanx.Agent.Tests/ --filter "Category=NeutralBenchmark"`
  - Full-Chain: `powershell -ExecutionPolicy Bypass -File .\scripts\run_fullchain_test.ps1`
  - Warning: NEVER omit filter (unfiltered run triggers ~3.5 min `Category=Live` cloud API calls).
- **Privileges**: Sensor executable requires administrator elevation for ETW kernel sessions (`/MANIFESTUAC` link flag in `src/Phalanx.Sensor/CMakeLists.txt`; never add manifest to `target_sources` -> LNK1327).
- **Secret Isolation**: Store credentials in local uncommitted files (`google-credentials.json`, `AppSettings.json`). Rely strictly on `PhalanxConfigurationManager` SSOT (never auto-probe environment variables). Enforce `.gitignore` exclusion.
- **Paths**: Use relative paths (`../Obsidian.Agent/`, etc.).
</critical_rules>

<context_triggers>
- **Overview & SLA**: Vision, SLA budgets, engineering values -> `../Obsidian.Agent/Phalanx/docs/00_project_overview.md`
- **Architecture**: System architecture, pipelines, IPC schemas -> `../Obsidian.Agent/Phalanx/docs/01_system_architecture.md`
- **AI Agent & Tools**: ReAct loops, prompt schemas, forensic tools -> `../Obsidian.Agent/Phalanx/docs/02_ai_agent_investigation_design.md`
- **Benchmarks**: Evasion scenarios, latency profiles -> `../Obsidian.Agent/Phalanx/docs/04_performance_benchmarks.md`
- **Roadmap & Handover**: New features, backlog, invariants -> `../Obsidian.Agent/Phalanx/docs/03_implementation_roadmap.md`
- **Troubleshooting**: Bugs, kernel edge cases, build issues -> `../Obsidian.Agent/troubleshooting/phalanx.md`
</context_triggers>

<post_action>
- **Log**: Document resolved bugs and kernel edge cases in `../Obsidian.Agent/troubleshooting/phalanx.md`.
- **Sync**: Update specifications in `../Obsidian.Agent/Phalanx/docs/` if architecture, tool contracts, or IPC schemas change.
</post_action>
