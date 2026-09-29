#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <timeapi.h>

#include <iostream>
#include <chrono>
#include <atomic>
#include <csignal>

#include "Common/Win32Handles.h"
#include "Queue/DoubleBufferedSwapQueue.h"
#include "Actuator/SafetyWatchdog.h"
#include "Actuator/ProcessActuator.h"
#include "Collector/EtwKernelCollector.h"
#include "Ipc/GrpcStreamClient.h"

#pragma comment(lib, "winmm.lib")

namespace {
std::atomic<bool> g_shutdown_requested{false};

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        std::cout << "\n🛑 [Shutdown] Console termination signal received. Initiating graceful shutdown..." << std::endl;
        g_shutdown_requested.store(true, std::memory_order_release);
        return TRUE;
    default:
        return FALSE;
    }
}

struct WindowsTimerGuard {
    WindowsTimerGuard() { ::timeBeginPeriod(1); }
    ~WindowsTimerGuard() { ::timeEndPeriod(1); }
};
} // namespace

int main(int argc, char* argv[]) {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);
    WindowsTimerGuard timer_guard;

    // 1. 명령줄 인자 파싱 (관리자 권한 확인 전 도움말 플래그 우선 처리)
    std::string endpoint = "127.0.0.1:50051";
    bool standalone = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--endpoint" && i + 1 < argc) {
            endpoint = argv[++i];
        } else if (arg == "--standalone") {
            standalone = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "사용법: Phalanx.Sensor.exe [--endpoint <ip:port>] [--standalone]\n"
                      << "  --endpoint <ip:port> : gRPC Core 원격 측정 엔드포인트 (기본값: 127.0.0.1:50051)\n"
                      << "  --standalone          : gRPC 서버 없이 로컬 콘솔에만 커널 이벤트를 출력하는 단독 실행 모드\n";
            return 0;
        }
    }

    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX EDR - C++20 네이티브 커널 텔레메트리 센서 (Phalanx.Sensor)            " << std::endl;
    std::cout << "================================================================================" << std::endl;

    // 2. 관리자 권한 확인 (ETW 커널 세션 생성 및 프로세스 액추에이터 제어에 필수)
    if (!Phalanx::Common::PrivilegeHelper::IsElevated()) {
        std::cerr << "❌ [접근 거부] Phalanx.Sensor는 실시간 ETW 커널 추적 세션 생성 및\n"
                  << "   프로세스 액추에이터 실행을 위해 반드시 '관리자 권한'이 필요합니다.\n"
                  << "   관리자 권한으로 다시 실행해 주십시오." << std::endl;
        return ERROR_ACCESS_DENIED;
    }

    if (Phalanx::Common::PrivilegeHelper::EnableDebugPrivilege()) {
        std::cout << "🔑 [권한] SeDebugPrivilege 활성화 성공." << std::endl;
    } else {
        std::cout << "⚠️ [권한] SeDebugPrivilege 활성화 실패. 일부 시스템 프로세스 제어가 제한될 수 있습니다." << std::endl;
    }

    ::SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 3. 동시성 큐 및 안전 워치독/액추에이터 초기화
    auto queue = std::make_shared<Phalanx::Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>>();
    auto watchdog = std::make_shared<Phalanx::Actuator::SafetyWatchdog>(std::chrono::milliseconds(10000));
    auto actuator = std::make_shared<Phalanx::Actuator::ProcessActuator>(watchdog);

    // 4. ETW 커널 이벤트 수집기 초기화 및 가동
    auto collector = std::make_shared<Phalanx::Collector::EtwKernelCollector>(queue);
    collector->SetProcessObserver([](const phalanx::ProcessEvent& ev) {
        std::cout << "🔍 [커널-프로세스] PID: " << ev.process_id()
                  << " | PPID: " << ev.parent_process_id()
                  << " | 이미지: " << ev.image_name()
                  << " | 커맨드라인: " << (ev.command_line().empty() ? "(없음)" : ev.command_line())
                  << std::endl;
    });

    if (!collector->Start()) {
        std::cerr << "❌ [수집기] ETW 커널 수집기 시작 실패!" << std::endl;
        return 1;
    }

    // 5. gRPC 양방향 스트리밍 IPC 파이프라인 초기화
    std::unique_ptr<Phalanx::Ipc::GrpcStreamClient> grpc_client;
    if (!standalone) {
        grpc_client = std::make_unique<Phalanx::Ipc::GrpcStreamClient>(endpoint, queue, actuator);
        grpc_client->Start();
        std::cout << "🌐 [IPC] gRPC 스트리밍 클라이언트 시작됨. 대상: " << endpoint << std::endl;
    } else {
        std::cout << "ℹ️ [IPC] 독립 실행(standalone) 모드로 동작 중 (gRPC 스트리밍 비활성화)." << std::endl;
    }

    std::cout << "✅ [Phalanx.Sensor] 센서 엔진 정상 가동 중. 종료하려면 Ctrl+C를 누르십시오.\n" << std::endl;

    // 6. 메인 루프 (종료 신호 감지 대기)
    while (!g_shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // 7. 정상 종료 및 리소스 해제 (Graceful Teardown)
    std::cout << "\n>>> Phalanx 센서 안전 종료 절차 진행 중..." << std::endl;
    if (grpc_client) {
        grpc_client->Stop();
    }
    collector->Stop();

    std::cout << ">>> 총 수집된 커널 이벤트: " << collector->EventsCaptured() << std::endl;
    if (grpc_client) {
        std::cout << ">>> 전송된 배치 수: " << grpc_client->BatchesSent() << std::endl;
        std::cout << ">>> 전송된 총 이벤트 수: " << grpc_client->EventsSent() << std::endl;
        std::cout << ">>> 수신된 완화 명령 수: " << grpc_client->CommandsReceived() << std::endl;
    }
    std::cout << ">>> 이중 버퍼 스왑 큐 유실(Dropped) 수: " << queue->DroppedCount() << std::endl;
    std::cout << ">>> 모든 리소스가 안전하게 정리되었습니다. 종료합니다." << std::endl;

    return 0;
}
