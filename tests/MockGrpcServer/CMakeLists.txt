set(SERVER_SOURCES
    main.cpp
)

add_executable(MockGrpcServer ${SERVER_SOURCES})

target_link_libraries(MockGrpcServer PRIVATE
    phalanx_proto
    gRPC::grpc++
    protobuf::libprotobuf
)
