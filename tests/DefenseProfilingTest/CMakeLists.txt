add_executable(MockNativeRansomware MockNativeRansomware.cpp)

set(PROFILING_TEST_SOURCES
    main.cpp
    ../../src/Phalanx.Sensor/Process/ProcessTree.cpp
    ../../src/Phalanx.Sensor/Rules/LocalRuleEngine.cpp
    ../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.cpp
    ../../src/Phalanx.Sensor/Actuator/ProcessActuator.cpp
    ../../src/Phalanx.Sensor/Collector/EtwKernelCollector.cpp
)

add_executable(DefenseProfilingTest ${PROFILING_TEST_SOURCES})

target_include_directories(DefenseProfilingTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Phalanx.Sensor
    ${KRABSETW_INCLUDE_DIRS}
)

target_link_libraries(DefenseProfilingTest PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
    tdh
    advapi32
    winmm
)
