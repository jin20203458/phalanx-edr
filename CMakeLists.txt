cmake_minimum_required(VERSION 3.24)

project(Phalanx CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure Unicode, NOMINMAX, and Lean-and-mean Windows definitions
add_compile_definitions(
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
)

if (MSVC)
    add_compile_options("/utf-8" "/EHsc" "/W4" "/permissive-")
endif()

# Find required dependencies
find_package(gRPC CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(asio-grpc REQUIRED)

find_path(KRABSETW_INCLUDE_DIRS "krabs.hpp")
if (NOT KRABSETW_INCLUDE_DIRS)
    message(FATAL_ERROR "krabs.hpp not found! Ensure krabsetw is installed via vcpkg.")
endif()
message(STATUS "Found krabsetw: ${KRABSETW_INCLUDE_DIRS}")

# -------------------------------------------------------------------------
# Protobuf / gRPC Generation
# -------------------------------------------------------------------------
set(PROTO_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(PROTO_FILE "${PROTO_SRC_DIR}/phalanx.proto")
set(GEN_SRC_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${GEN_SRC_DIR})

set(GEN_PROTO_SRC "${GEN_SRC_DIR}/phalanx.pb.cc")
set(GEN_PROTO_HDR "${GEN_SRC_DIR}/phalanx.pb.h")
set(GEN_GRPC_SRC "${GEN_SRC_DIR}/phalanx.grpc.pb.cc")
set(GEN_GRPC_HDR "${GEN_SRC_DIR}/phalanx.grpc.pb.h")

set(GRPC_CPP_PLUGIN_PATH $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

add_custom_command(
    OUTPUT "${GEN_PROTO_SRC}" "${GEN_PROTO_HDR}" "${GEN_GRPC_SRC}" "${GEN_GRPC_HDR}"
    COMMAND protobuf::protoc
    ARGS --proto_path="${PROTO_SRC_DIR}"
         --cpp_out="${GEN_SRC_DIR}"
         --grpc_out="${GEN_SRC_DIR}"
         --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN_PATH}"
         "${PROTO_FILE}"
    DEPENDS "${PROTO_FILE}"
    COMMENT "Generating gRPC and Protobuf C++ sources from ${PROTO_FILE}"
)

add_library(phalanx_proto STATIC
    ${GEN_PROTO_SRC}
    ${GEN_PROTO_HDR}
    ${GEN_GRPC_SRC}
    ${GEN_GRPC_HDR}
)

target_include_directories(phalanx_proto PUBLIC
    ${GEN_SRC_DIR}
)

target_link_libraries(phalanx_proto PUBLIC
    gRPC::grpc++
    protobuf::libprotobuf
)

# Subdirectories
add_subdirectory(src/Phalanx.Sensor)
add_subdirectory(tests)
