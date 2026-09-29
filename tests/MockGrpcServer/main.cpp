#include <iostream>
#include <memory>
#include <string>
#include <grpcpp/grpcpp.h>
#include "phalanx.grpc.pb.h"

class MockPhalanxServiceImpl final : public phalanx::PhalanxService::Service {
public:
    grpc::Status StreamTelemetry(grpc::ServerContext* /*context*/,
                                 grpc::ServerReaderWriter<phalanx::MitigationCommand, phalanx::TelemetryBatch>* stream) override {
        std::cout << "⚡ [MockServer] StreamTelemetry client connected." << std::endl;
        phalanx::TelemetryBatch batch;

        while (stream->Read(&batch)) {
            size_t proc_count = batch.process_events_size();
            std::cout << "📦 [MockServer] Received batch with " << proc_count << " process events." << std::endl;

            for (const auto& pe : batch.process_events()) {
                std::cout << "   ↳ PID: " << pe.process_id()
                          << " | PPID: " << pe.parent_process_id()
                          << " | Image: " << pe.image_name()
                          << " | Cmd: " << pe.command_line() << std::endl;

                // Simulate reflex kill rule on test processes
                if (pe.image_name().find("powershell") != std::string::npos ||
                    pe.image_name().find("test_target") != std::string::npos) {
                    phalanx::MitigationCommand cmd;
                    cmd.set_action(phalanx::MitigationCommand::ACTION_KILL);
                    cmd.set_target_pid(pe.process_id());
                    cmd.set_reason("Reflex Trigger: Malicious script executor detected");
                    stream->Write(cmd);
                    std::cout << "🛡️ [MockServer] Sent ACTION_KILL to sensor for PID: " << pe.process_id() << std::endl;
                }
            }
        }

        std::cout << "🔌 [MockServer] StreamTelemetry client disconnected." << std::endl;
        return grpc::Status::OK;
    }
};

int main(int argc, char* argv[]) {
    std::string server_address("0.0.0.0:50051");
    if (argc > 1) {
        server_address = argv[1];
    }

    MockPhalanxServiceImpl service;
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "🚀 [MockServer] Phalanx gRPC Server listening on " << server_address << std::endl;
    server->Wait();
    return 0;
}
