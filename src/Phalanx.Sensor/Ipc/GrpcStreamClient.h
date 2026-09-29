#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <functional>
#include <chrono>
#include "../Queue/DoubleBufferedSwapQueue.h"
#include "../Actuator/ProcessActuator.h"
#include "phalanx.pb.h"
#include "phalanx.grpc.pb.h"

namespace Phalanx::Ipc {

// 방어 명령 수신 시 실행될 콜백 핸들러 타입
using CommandHandler = std::function<void(const phalanx::MitigationCommand&)>;

/**
 * @brief Phalanx 텔레메트리 전송을 위한 고속 비동기 양방향 gRPC 스트리밍 클라이언트.
 *
 * asio-grpc C++20 코루틴 파이프라인:
 *  - 송신 루프: 10ms 주기로 DoubleBufferedSwapQueue를 플러시하여 TelemetryBatch 일괄 전송.
 *  - 수신 루프: Core에서 하달하는 MitigationCommand를 비동기 수신하여 ProcessActuator로 디스패치.
 *  - 연결 두절 시 지수 백오프 기반 자동 재연결 지원.
 */
class GrpcStreamClient {
public:
    GrpcStreamClient(std::string target_endpoint,
                     std::shared_ptr<Queue::DoubleBufferedSwapQueue<phalanx::ProcessEvent>> queue,
                     std::shared_ptr<Actuator::ProcessActuator> actuator);
    ~GrpcStreamClient();

    GrpcStreamClient(const GrpcStreamClient&) = delete;
    GrpcStreamClient& operator=(const GrpcStreamClient&) = delete;

    // 사용자 정의 방어 명령 핸들러 등록 (테스트 및 모니터링용)
    void SetCustomCommandHandler(CommandHandler handler);

    /**
     * @brief 백그라운드 asio-grpc 스레드 및 양방향 스트리밍 루프를 시작
     */
    bool Start();

    /**
     * @brief 활성 스트림을 취소하고 클라이언트를 안전하게 종료
     */
    void Stop();

    // 서버와의 스트림 연결 상태 확인
    [[nodiscard]] bool IsConnected() const noexcept {
        return is_connected_.load(std::memory_order_relaxed);
    }

    // 전송된 총 배치(Batch) 수 반환
    [[nodiscard]] size_t BatchesSent() const noexcept {
        return batches_sent_.load(std::memory_order_relaxed);
    }

    // 전송된 총 이벤트 개수 반환
    [[nodiscard]] size_t EventsSent() const noexcept {
        return events_sent_.load(std::memory_order_relaxed);
    }

    // 수신된 총 방어 명령 개수 반환
    [[nodiscard]] size_t CommandsReceived() const noexcept {
        return commands_received_.load(std::memory_order_relaxed);
    }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::atomic<bool> is_connected_{false};
    std::atomic<size_t> batches_sent_{0};
    std::atomic<size_t> events_sent_{0};
    std::atomic<size_t> commands_received_{0};
};

} // namespace Phalanx::Ipc
