set(CROSS_E2E_SOURCES
    main.cpp
    ../../src/Phalanx.Sensor/Ipc/GrpcStreamClient.cpp
    ../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.cpp
    ../../src/Phalanx.Sensor/Actuator/ProcessActuator.cpp
    ../../src/Phalanx.Sensor/Process/ProcessTree.cpp
)

add_executable(FullChainCrossE2ETest ${CROSS_E2E_SOURCES})

target_include_directories(FullChainCrossE2ETest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Phalanx.Sensor
)

target_link_libraries(FullChainCrossE2ETest PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
    asio-grpc::asio-grpc
    tdh
    advapi32
    winmm
)
