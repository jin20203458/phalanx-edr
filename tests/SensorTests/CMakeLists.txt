set(TEST_SOURCES
    main.cpp
    ../../src/Phalanx.Sensor/Actuator/SafetyWatchdog.cpp
    ../../src/Phalanx.Sensor/Actuator/ProcessActuator.cpp
)

add_executable(SensorTests ${TEST_SOURCES})

target_include_directories(SensorTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/Phalanx.Sensor
)

target_link_libraries(SensorTests PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
)
