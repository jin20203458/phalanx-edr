set(E2E_SOURCES
    main.cpp
    ../../src/Phalanx.Sensor/Ipc/GrpcStreamClient.cpp
    ../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.cpp
    ../../src/Phalanx.Sensor/Actuator/ProcessActuator.cpp
    ../../src/Phalanx.Sensor/Process/ProcessTree.cpp
)

add_executable(IpcE2ETest ${E2E_SOURCES})

target_include_directories(IpcE2ETest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Phalanx.Sensor
)

target_link_libraries(IpcE2ETest PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
    asio-grpc::asio-grpc
    tdh
    advapi32
    winmm
)
