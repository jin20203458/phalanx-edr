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

    // 1. Parse Arguments (check help before elevation check)
    std::string endpoint = "127.0.0.1:50051";
    bool standalone = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--endpoint" && i + 1 < argc) {
            endpoint = argv[++i];
        } else if (arg == "--standalone") {
            standalone = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: Phalanx.Sensor.exe [--endpoint <ip:port>] [--standalone]\n"
                      << "  --endpoint <ip:port> : gRPC Core telemetry endpoint (default: 127.0.0.1:50051)\n"
                      << "  --standalone          : Run without gRPC server, logging kernel events locally\n";
            return 0;
        }
    }

    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX EDR - C++20 Native Kernel Telemetry Sensor (Phalanx.Sensor)          " << std::endl;
    std::cout << "================================================================================" << std::endl;

    // 2. Check Administrator Elevation
    if (!Phalanx::Common::PrivilegeHelper::IsElevated()) {
        std::cerr << "❌ [Access Denied] Phalanx.Sensor requires Administrator elevation to create\n"
                  << "   real-time ETW kernel trace sessions and manage process actuators.\n"
                  << "   Please run this executable as Administrator." << std::endl;
        return ERROR_ACCESS_DENIED;
    }

    if (Phalanx::Common::PrivilegeHelper::EnableDebugPrivilege()) {
        std::cout << "🔑 [Privilege] SeDebugPrivilege enabled successfully." << std::endl;
    } else {
        std::cout << "⚠️ [Privilege] Could not enable SeDebugPrivilege. Some system processes may be protected." << std::endl;
    }

    ::SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 3. Initialize Concurrency Queue & Actuators
    auto queue = std::make_shared<Phalanx::Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>>();
    auto watchdog = std::make_shared<Phalanx::Actuator::SafetyWatchdog>(std::chrono::milliseconds(10000));
    auto actuator = std::make_shared<Phalanx::Actuator::ProcessActuator>(watchdog);

    // 4. Initialize ETW Kernel Collector
    auto collector = std::make_shared<Phalanx::Collector::EtwKernelCollector>(queue);
    collector->SetProcessObserver([](const phalanx::ProcessEvent& ev) {
        std::cout << "🔍 [Kernel-Process] PID: " << ev.process_id()
                  << " | PPID: " << ev.parent_process_id()
                  << " | Image: " << ev.image_name()
                  << " | Cmd: " << (ev.command_line().empty() ? "(none)" : ev.command_line())
                  << std::endl;
    });

    if (!collector->Start()) {
        std::cerr << "❌ [Collector] Failed to start ETW Kernel Collector!" << std::endl;
        return 1;
    }

    // 5. Initialize gRPC Streaming Pipeline
    std::unique_ptr<Phalanx::Ipc::GrpcStreamClient> grpc_client;
    if (!standalone) {
        grpc_client = std::make_unique<Phalanx::Ipc::GrpcStreamClient>(endpoint, queue, actuator);
        grpc_client->Start();
        std::cout << "🌐 [IPC] gRPC Streaming client started. Target: " << endpoint << std::endl;
    } else {
        std::cout << "ℹ️ [IPC] Running in standalone mode (no gRPC streaming)." << std::endl;
    }

    std::cout << "✅ [Phalanx.Sensor] Sensor engine running. Press Ctrl+C to terminate.\n" << std::endl;

    // 6. Main Loop
    while (!g_shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    // 7. Graceful Teardown
    std::cout << "\n>>> Shuting down Phalanx Sensor..." << std::endl;
    if (grpc_client) {
        grpc_client->Stop();
    }
    collector->Stop();

    std::cout << ">>> Total events captured: " << collector->EventsCaptured() << std::endl;
    if (grpc_client) {
        std::cout << ">>> Total batches sent: " << grpc_client->BatchesSent() << std::endl;
        std::cout << ">>> Total events sent: " << grpc_client->EventsSent() << std::endl;
        std::cout << ">>> Total commands received: " << grpc_client->CommandsReceived() << std::endl;
    }
    std::cout << ">>> DoubleBufferedSwapQueue dropped count: " << queue->DroppedCount() << std::endl;
    std::cout << ">>> Shutdown complete. Goodbye." << std::endl;

    return 0;
}
