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
#include <grpcpp/grpcpp.h>
#include "phalanx.grpc.pb.h"
#include "../../src/Phalanx.Sensor/Queue/DoubleBufferedSwapQueue.h"
#include "../../src/Phalanx.Sensor/Ipc/GrpcStreamClient.h"
#include "../../src/Phalanx.Sensor/Actuator/ProcessActuator.h"

class MockServerImpl final : public phalanx::PhalanxService::Service {
public:
    std::atomic<bool> batch_received{false};
    std::atomic<bool> command_sent{false};

    grpc::Status StreamTelemetry(grpc::ServerContext*,
                                 grpc::ServerReaderWriter<phalanx::MitigationCommand, phalanx::TelemetryBatch>* stream) override {
        phalanx::TelemetryBatch batch;
        while (stream->Read(&batch)) {
            batch_received.store(true, std::memory_order_release);
            for (const auto& pe : batch.process_events()) {
                if (pe.process_id() == 7777) {
                    phalanx::MitigationCommand cmd;
                    cmd.set_action(phalanx::MitigationCommand::ACTION_KILL);
                    cmd.set_target_pid(pe.process_id());
                    cmd.set_reason("Reflex rule trigger: powershell test");
                    stream->Write(cmd);
                    command_sent.store(true, std::memory_order_release);
                }
            }
        }
        return grpc::Status::OK;
    }
};

int main() {
    ::SetConsoleOutputCP(CP_UTF8);
    std::cout << "================================================================================" << std::endl;
    std::cout << "   PHALANX gRPC IPC END-TO-END VERIFICATION TEST                               " << std::endl;
    std::cout << "================================================================================" << std::endl;

    std::string server_addr("127.0.0.1:50099");
    MockServerImpl service;
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_addr, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    auto server = builder.BuildAndStart();
    std::cout << "🚀 [E2E Test] In-process Mock gRPC Server listening on " << server_addr << std::endl;

    auto queue = std::make_shared<Phalanx::Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>>();
    auto client = std::make_unique<Phalanx::Ipc::GrpcStreamClient>(server_addr, queue, nullptr);

    std::atomic<bool> client_cmd_received{false};
    client->SetCustomCommandHandler([&client_cmd_received](const phalanx::MitigationCommand& cmd) {
        if (cmd.target_pid() == 7777 && cmd.action() == phalanx::MitigationCommand::ACTION_KILL) {
            std::cout << "🛡️ [E2E Test] Client callback received MitigationCommand: ACTION_KILL for PID "
                      << cmd.target_pid() << std::endl;
            client_cmd_received.store(true, std::memory_order_release);
        }
    });

    client->Start();

    // Wait for connection
    int attempts = 0;
    while (!client->IsConnected() && attempts++ < 30) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (!client->IsConnected()) {
        std::cerr << "❌ [E2E Test] Failed to connect to gRPC server!" << std::endl;
        server->Shutdown();
        return 1;
    }
    std::cout << "✅ [E2E Test] gRPC Stream connected!" << std::endl;

    // Push test event
    std::cout << "📦 [E2E Test] Pushing synthetic malicious process event (PID 7777) into DoubleBufferedSwapQueue..." << std::endl;
    phalanx::ProcessEvent ev;
    ev.set_process_id(7777);
    ev.set_parent_process_id(1000);
    ev.set_image_name("powershell.exe");
    ev.set_command_line("powershell.exe -enc dGVzdA==");
    ev.set_timestamp_ns(123456789);
    queue->Push(std::move(ev));

    // Wait for round-trip response
    attempts = 0;
    while (!client_cmd_received.load(std::memory_order_acquire) && attempts++ < 30) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    client->Stop();
    server->Shutdown();

    if (!service.batch_received.load()) {
        std::cerr << "❌ [E2E Test] Server did not receive TelemetryBatch!" << std::endl;
        return 1;
    }
    if (!service.command_sent.load()) {
        std::cerr << "❌ [E2E Test] Server did not dispatch MitigationCommand!" << std::endl;
        return 1;
    }
    if (!client_cmd_received.load()) {
        std::cerr << "❌ [E2E Test] Client did not receive MitigationCommand!" << std::endl;
        return 1;
    }

    std::cout << "================================================================================" << std::endl;
    std::cout << "🎉 FULL BIDIRECTIONAL gRPC PIPELINE ROUNDTRIP SUCCESSFUL! (Exit Code 0)         " << std::endl;
    std::cout << "================================================================================" << std::endl;
    return 0;
}
