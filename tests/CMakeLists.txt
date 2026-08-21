

#############################################
#               Build volePSI_Tests            #
#############################################


set(SRCS
	"UnitTests.cpp"
	)
	
if(VOLE_PSI_ENABLE_CPSI)
    list(APPEND SRCS
        "RsCpsi_Tests.cpp"
        "RsPsiInnerproduct_Perf.cpp"
        "Pso_Tests.cpp"
    )
endif()
if(VOLE_PSI_ENABLE_SEAL)
    list(APPEND SRCS "RsPsiInnerproduct_SEAL_Tests.cpp")
endif()
add_library(volePSI_Tests ${SRCS})

target_link_libraries(volePSI_Tests volePSI)


if(MSVC)
    target_compile_options(volePSI_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${VOLE_PSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(volePSI_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${VOLE_PSI_STD_VER}>)
endif()
