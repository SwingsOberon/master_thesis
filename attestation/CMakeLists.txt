project (optee_example_attestation C)

set (SRC host/main.c host/kern.c host/kern.h)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
               PRIVATE include/linux/include
               PRIVATE include/linux/arch/arm64/include
               PRIVATE include/linux/arch/arm64/include/generated
               PRIVATE include/linux/include/uapi
               PRIVATE include/linux/arch/arm64/include/uapi)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
