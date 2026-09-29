#include "ProcessTree.h"
#include "../Common/Win32Handles.h"
#include <tlhelp32.h>
#include <algorithm>
#include <unordered_set>
#include <chrono>

namespace Phalanx::Process {

ProcessTree::ProcessTree(size_t max_tombstones)
    : max_tombstones_(max_tombstones) {
}

bool ProcessTree::InitializeFromSnapshot() {
    HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return false;
    }
    Common::UniqueHandle snapGuard(hSnap);

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!::Process32FirstW(hSnap, &pe)) {
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(rw_lock_);
    nodes_.clear();
    tombstone_queue_.clear();

    size_t loaded = 0;
    do {
        ProcessNode node;
        node.pid = static_cast<uint32_t>(pe.th32ProcessID);
        node.ppid = static_cast<uint32_t>(pe.th32ParentProcessID);
        node.image_name = Common::Utf16ToUtf8(pe.szExeFile);
        node.is_alive = true;
        nodes_.emplace(node.pid, std::move(node));
        loaded++;
    } while (::Process32NextW(hSnap, &pe));

    // 로드된 프로세스 간 부모-자식 링크 형성
    for (auto& [pid, node] : nodes_) {
        if (node.ppid != 0 && node.ppid != pid) {
            auto parent_it = nodes_.find(node.ppid);
            if (parent_it != nodes_.end()) {
                parent_it->second.children_pids.push_back(pid);
            }
        }
    }

    return loaded > 0;
}

void ProcessTree::OnProcessStart(const phalanx::ProcessEvent& event) {
    ProcessNode node;
    node.pid = event.process_id();
    node.ppid = event.parent_process_id();
    node.image_name = event.image_name();
    node.command_line = event.command_line();
    node.start_time = event.timestamp_ns();
    node.session_id = event.session_id();
    node.token_elevation_type = event.token_elevation_type();
    node.is_alive = true;

    std::unique_lock<std::shared_mutex> lock(rw_lock_);
    InsertOrOverwriteNodeInternal(std::move(node));
}

void ProcessTree::OnProcessStart(uint32_t pid, uint32_t ppid, std::string image_name,
                                std::string command_line, uint64_t start_time,
                                uint32_t session_id, uint32_t token_elevation_type) {
    ProcessNode node;
    node.pid = pid;
    node.ppid = ppid;
    node.image_name = std::move(image_name);
    node.command_line = std::move(command_line);
    node.start_time = start_time;
    node.session_id = session_id;
    node.token_elevation_type = token_elevation_type;
    node.is_alive = true;

    std::unique_lock<std::shared_mutex> lock(rw_lock_);
    InsertOrOverwriteNodeInternal(std::move(node));
}

void ProcessTree::InsertOrOverwriteNodeInternal(ProcessNode&& node) {
    uint32_t pid = node.pid;
    uint32_t ppid = node.ppid;

    auto it = nodes_.find(pid);
    if (it != nodes_.end()) {
        // PID 재사용: 기존 노드가 가지고 있던 부모의 children_pids 목록에서 이 pid를 제거
        uint32_t old_ppid = it->second.ppid;
        if (old_ppid != ppid && old_ppid != 0) {
            auto old_parent_it = nodes_.find(old_ppid);
            if (old_parent_it != nodes_.end()) {
                auto& vec = old_parent_it->second.children_pids;
                vec.erase(std::remove(vec.begin(), vec.end(), pid), vec.end());
            }
        }

        // PID 재사용: 기존 노드를 부모로 가리키던 자식들의 링크 절단 (새 프로세스로의 유령 입양 방지)
        for (uint32_t child_pid : it->second.children_pids) {
            auto child_it = nodes_.find(child_pid);
            if (child_it != nodes_.end() && child_it->second.ppid == pid) {
                child_it->second.ppid = 0;
            }
        }

        it->second = std::move(node);
    } else {
        nodes_.emplace(pid, std::move(node));
    }

    // 신규 부모와 자식 링크 형성
    if (ppid != 0 && ppid != pid) {
        auto parent_it = nodes_.find(ppid);
        if (parent_it != nodes_.end()) {
            auto& ch = parent_it->second.children_pids;
            if (std::find(ch.begin(), ch.end(), pid) == ch.end()) {
                ch.push_back(pid);
            }
        }
    }
}

void ProcessTree::OnProcessStop(uint32_t pid, uint64_t exit_timestamp) {
    std::unique_lock<std::shared_mutex> lock(rw_lock_);
    auto it = nodes_.find(pid);
    if (it != nodes_.end()) {
        if (it->second.is_alive) {
            it->second.is_alive = false;
            it->second.exit_time = exit_timestamp ? exit_timestamp :
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            tombstone_queue_.push_back(pid);
        }
    }

    // Tombstone 상한선 초과 시 가장 오래된 Tombstone 즉시 증발(Evict)
    while (tombstone_queue_.size() > max_tombstones_) {
        EvictOldestTombstoneInternal();
    }
}

void ProcessTree::EvictOldestTombstoneInternal() {
    if (tombstone_queue_.empty()) return;
    uint32_t evict_pid = tombstone_queue_.front();
    tombstone_queue_.pop_front();

    auto it = nodes_.find(evict_pid);
    if (it != nodes_.end() && !it->second.is_alive) {
        // 부모의 자식 목록에서도 정리 (상향 링크 절단)
        if (it->second.ppid != 0) {
            auto parent_it = nodes_.find(it->second.ppid);
            if (parent_it != nodes_.end()) {
                auto& ch = parent_it->second.children_pids;
                ch.erase(std::remove(ch.begin(), ch.end(), evict_pid), ch.end());
            }
        }

        // 자식들의 부모 링크 정리 (하향 링크 절단: 고아 처리)
        for (uint32_t child_pid : it->second.children_pids) {
            auto child_it = nodes_.find(child_pid);
            if (child_it != nodes_.end() && child_it->second.ppid == evict_pid) {
                child_it->second.ppid = 0;
            }
        }

        nodes_.erase(it);
    }
}

std::vector<ProcessNode> ProcessTree::GetAncestry(uint32_t pid, size_t max_depth, bool include_self) const {
    std::shared_lock<std::shared_mutex> lock(rw_lock_);
    std::vector<ProcessNode> ancestry;
    ancestry.reserve(max_depth + (include_self ? 1 : 0));

    auto it = nodes_.find(pid);
    if (it == nodes_.end()) {
        return ancestry;
    }

    if (include_self) {
        ancestry.push_back(it->second);
    }

    uint32_t curr_ppid = it->second.ppid;
    std::unordered_set<uint32_t> visited;
    visited.insert(pid);

    size_t target_count = max_depth + (include_self ? 1 : 0);
    while (ancestry.size() < target_count && curr_ppid != 0) {
        if (!visited.insert(curr_ppid).second) {
            // 순환 참조 방지 (PID == PPID 등)
            break;
        }
        auto p_it = nodes_.find(curr_ppid);
        if (p_it == nodes_.end()) {
            break;
        }
        ancestry.push_back(p_it->second);
        curr_ppid = p_it->second.ppid;
    }

    return ancestry;
}

std::optional<ProcessNode> ProcessTree::FindNode(uint32_t pid) const {
    std::shared_lock<std::shared_mutex> lock(rw_lock_);
    auto it = nodes_.find(pid);
    if (it != nodes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t ProcessTree::ActiveNodeCount() const {
    std::shared_lock<std::shared_mutex> lock(rw_lock_);
    size_t count = 0;
    for (const auto& [_, node] : nodes_) {
        if (node.is_alive) {
            count++;
        }
    }
    return count;
}

size_t ProcessTree::TombstoneCount() const {
    std::shared_lock<std::shared_mutex> lock(rw_lock_);
    return tombstone_queue_.size();
}

size_t ProcessTree::TotalNodeCount() const {
    std::shared_lock<std::shared_mutex> lock(rw_lock_);
    return nodes_.size();
}

void ProcessTree::Clear() {
    std::unique_lock<std::shared_mutex> lock(rw_lock_);
    nodes_.clear();
    tombstone_queue_.clear();
}

} // namespace Phalanx::Process
