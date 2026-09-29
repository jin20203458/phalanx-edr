#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <deque>
#include <optional>
#include <shared_mutex>
#include "phalanx.pb.h"

namespace Phalanx::Process {

/**
 * @brief PID 재사용 방지를 위한 (start_time_ns << 32) | pid 조합의 전역 고유 식별자(process_guid) 생성
 */
inline uint64_t GenerateProcessGuid(uint32_t pid, uint64_t start_time_ns) noexcept {
    return (start_time_ns << 32) | static_cast<uint64_t>(pid);
}

/**
 * @brief C++ RAM 상에서 관리되는 개별 프로세스 트리 노드.
 */
struct ProcessNode {
    uint32_t pid{0};
    uint32_t ppid{0};
    uint64_t guid{0};
    uint64_t parent_guid{0};
    std::string image_name;
    std::string command_line;
    uint64_t start_time{0};
    uint64_t exit_time{0};
    uint64_t exit_code{0};
    uint32_t session_id{0};
    uint32_t token_elevation_type{0};
    bool is_alive{true};
    std::vector<uint32_t> children_pids;
};

/**
 * @brief 고속 동시성(RW-Lock) 기반 인메모리 프로세스 트리(DAG).
 *
 * 주요 기능:
 *  1. 기동 시점 Toolhelp32 프로세스 스냅샷 기반 트리 워밍업(Snapshot Warm-up).
 *  2. ETW ProcessStart 연동: 노드 O(1) 삽입, 부모-자식 링크 형성, Windows PID 재사용 안전 덮어쓰기.
 *  3. ETW ProcessStop 연동: Tombstone 전환 및 최대 10,000개 메모리 상한선(Bounded Eviction) 유지.
 *  4. 족보 횡단(Ancestry Traversal): 10μs 이내(실측 < 1μs) 부모/조부모 체인 역추적.
 */
class ProcessTree {
public:
    static constexpr size_t DEFAULT_MAX_TOMBSTONES = 10000;

    explicit ProcessTree(size_t max_tombstones = DEFAULT_MAX_TOMBSTONES);
    ~ProcessTree() = default;

    ProcessTree(const ProcessTree&) = delete;
    ProcessTree& operator=(const ProcessTree&) = delete;

    /**
     * @brief 엔진 기동 시점 Toolhelp32 스냅샷을 1회 호출하여 현재 활성 프로세스 목록을 트리에 사전 로드.
     * @return 성공 여부 (로드된 활성 프로세스 수 > 0)
     */
    bool InitializeFromSnapshot();

    /**
     * @brief 현재 활성(is_alive == true) 상태인 모든 프로세스를 LIFECYCLE_SNAPSHOT 이벤트 벡터로 일괄 추출.
     *        C# 관제기 최초 접속 시 1회 덤프 핸드셰이크용으로 사용됩니다.
     */
    [[nodiscard]] std::vector<phalanx::ProcessEvent> GetActiveSnapshotEvents() const;

    /**
     * @brief ETW ProcessStart 수신 시 트리 노드 삽입 및 부모-자식 관계 링크.
     *        동일 PID가 이미 존재하는 경우 PID 재사용으로 간주하여 이전 노드를 덮어쓰고 링크를 갱신합니다.
     */
    void OnProcessStart(const phalanx::ProcessEvent& event);

    /**
     * @brief 수동 필드 기반 OnProcessStart 오버로드 (단위 테스트 및 스냅샷 주입용)
     */
    void OnProcessStart(uint32_t pid, uint32_t ppid, std::string image_name,
                        std::string command_line = "", uint64_t start_time = 0,
                        uint32_t session_id = 0, uint32_t token_elevation_type = 0);

    /**
     * @brief ETW ProcessStop 수신 시 노드를 Tombstone 상태로 전환하고 큐에 등록.
     *        Tombstone 개수가 상한(기본 10,000개)을 초과하면 가장 오래된 종료 노드를 즉시 제거합니다.
     * @return 종료된 프로세스 노드의 정보 (이미 종료되었거나 없으면 std::nullopt)
     */
    std::optional<ProcessNode> OnProcessStop(uint32_t pid, uint64_t exit_timestamp = 0, uint64_t exit_code = 0);

    /**
     * @brief 특정 PID의 부모/조부모 계층 족보를 10μs 이내에 역추적하여 반환.
     * @param pid 대상 프로세스 PID
     * @param max_depth 탐색할 최대 부모 깊이 (기본값: 5)
     * @param include_self 결과 벡터의 맨 앞에 자기 자신 노드를 포함할지 여부
     * @return 부모 체인 노드 목록 (직계 부모 -> 조부모 -> 증조부모 ...)
     */
    [[nodiscard]] std::vector<ProcessNode> GetAncestry(uint32_t pid, size_t max_depth = 5, bool include_self = false) const;

    /**
     * @brief 특정 PID의 노드 정보를 O(1)로 조회.
     */
    [[nodiscard]] std::optional<ProcessNode> FindNode(uint32_t pid) const;

    /**
     * @brief 활성(is_alive == true) 상태인 프로세스 노드 수 반환.
     */
    [[nodiscard]] size_t ActiveNodeCount() const;

    /**
     * @brief 종료(is_alive == false)된 Tombstone 노드 수 반환.
     */
    [[nodiscard]] size_t TombstoneCount() const;

    /**
     * @brief 트리에 보관된 총 노드 수 (Active + Tombstone) 반환.
     */
    [[nodiscard]] size_t TotalNodeCount() const;

    /**
     * @brief 트리 내 모든 노드 및 Tombstone 큐 초기화.
     */
    void Clear();

private:
    void InsertOrOverwriteNodeInternal(ProcessNode&& node);
    void EvictOldestTombstoneInternal();

    mutable std::shared_mutex rw_lock_;
    std::unordered_map<uint32_t, ProcessNode> nodes_;
    std::deque<uint32_t> tombstone_queue_;
    size_t max_tombstones_{DEFAULT_MAX_TOMBSTONES};
};

} // namespace Phalanx::Process
