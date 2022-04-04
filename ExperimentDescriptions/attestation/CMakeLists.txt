project (optee_example_attest C)

set (SRC host/main.c host/kern.c host/kern.h)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include
			   PRIVATE ../../linux/include
			   PRIVATE ../../linux/arch/arm64/include
			   PRIVATE ../../linux/arch/arm64/include/generated
			   PRIVATE ../../linux/arch/arm64/include/uapi)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
