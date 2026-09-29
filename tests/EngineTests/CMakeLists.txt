set(ENGINE_TEST_SOURCES
    main.cpp
    ../../src/Phalanx.Sensor/Process/ProcessTree.cpp
    ../../src/Phalanx.Sensor/Rules/LocalRuleEngine.cpp
    ../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.cpp
    ../../src/Phalanx.Sensor/Actuator/ProcessActuator.cpp
)

add_executable(EngineTests ${ENGINE_TEST_SOURCES})

target_include_directories(EngineTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Phalanx.Sensor
)

target_link_libraries(EngineTests PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
)
