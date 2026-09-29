set(SENSOR_SOURCES
    main.cpp
    Actuator/SafetyWatchdog.h
    Actuator/SafetyWatchdog.cpp
    Actuator/ProcessActuator.h
    Actuator/ProcessActuator.cpp
    Collector/EtwKernelCollector.h
    Collector/EtwKernelCollector.cpp
    Queue/DoubleBufferedSwapQueue.h
    Ipc/GrpcStreamClient.h
    Ipc/GrpcStreamClient.cpp
    Common/Win32Handles.h
)

add_executable(Phalanx.Sensor ${SENSOR_SOURCES})

target_include_directories(Phalanx.Sensor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${KRABSETW_INCLUDE_DIRS}
)

target_link_libraries(Phalanx.Sensor PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
    Boost::system
    asio-grpc::asio-grpc
    tdh
    advapi32
    winmm
)

if (MSVC)
    set_target_properties(Phalanx.Sensor PROPERTIES
        LINK_FLAGS "/MANIFEST:EMBED /MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()
