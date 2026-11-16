cmake_minimum_required(VERSION 3.10...3.31)
# set(CMAKE_C_COMPILER "clang")
# set(CMAKE_CXX_COMPILER "clang++")

project(Apfs)

option(USE_FUSE3 "Use the FUSE 3 library (required on 32-bit systems)" ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -march=native -fsanitize=undefined")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -march=native -fsanitize=undefined")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")

include_directories(.)
include_directories(SYSTEM 3rdparty/lzfse/src)

add_library(lzfse
	3rdparty/lzfse/src/lzfse.h
	3rdparty/lzfse/src/lzfse_decode.c
	3rdparty/lzfse/src/lzfse_decode_base.c
	3rdparty/lzfse/src/lzfse_encode.c
	3rdparty/lzfse/src/lzfse_encode_base.c
	3rdparty/lzfse/src/lzfse_encode_tables.h
	3rdparty/lzfse/src/lzfse_fse.c
	3rdparty/lzfse/src/lzfse_fse.h
	3rdparty/lzfse/src/lzfse_internal.h
	3rdparty/lzfse/src/lzfse_tunables.h
	3rdparty/lzfse/src/lzvn_decode_base.c
	3rdparty/lzfse/src/lzvn_decode_base.h
	3rdparty/lzfse/src/lzvn_encode_base.c
	3rdparty/lzfse/src/lzvn_encode_base.h
	)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
	target_compile_options(lzfse PRIVATE -Wno-sign-compare -Wno-unused-parameter)
endif()

add_library(crypto
	Crypto/Aes.cpp
	Crypto/Aes.h
	Crypto/AesXts.cpp
	Crypto/AesXts.h
	Crypto/Asn1Der.cpp
	Crypto/Asn1Der.h
	Crypto/Crypto.cpp
	Crypto/Crypto.h
	Crypto/Des.cpp
	Crypto/Des.h
	Crypto/Sha1.cpp
	Crypto/Sha1.h
	Crypto/Sha256.cpp
	Crypto/Sha256.h
	Crypto/TripleDes.cpp
	Crypto/TripleDes.h
)

add_library(apfs
	ApfsLib/ApfsContainer.cpp
	ApfsLib/ApfsContainer.h
	ApfsLib/ApfsDir.cpp
	ApfsLib/ApfsDir.h
	ApfsLib/ApfsNodeMapper.cpp
	ApfsLib/ApfsNodeMapper.h
	ApfsLib/ApfsNodeMapperBTree.cpp
	ApfsLib/ApfsNodeMapperBTree.h
	ApfsLib/ApfsVolume.cpp
	ApfsLib/ApfsVolume.h
	ApfsLib/BlockDumper.cpp
	ApfsLib/BlockDumper.h
	ApfsLib/BTree.cpp
	ApfsLib/BTree.h
	ApfsLib/CheckPointMap.cpp
	ApfsLib/CheckPointMap.h
	ApfsLib/Crc32.cpp
	ApfsLib/Crc32.h
	ApfsLib/Decmpfs.cpp
	ApfsLib/Decmpfs.h
	ApfsLib/Device.cpp
	ApfsLib/Device.h
	ApfsLib/DeviceDMG.cpp
	ApfsLib/DeviceDMG.h
	ApfsLib/DeviceLinux.cpp
	ApfsLib/DeviceLinux.h
	ApfsLib/DeviceMac.cpp
	ApfsLib/DeviceMac.h
	ApfsLib/DeviceSparseImage.cpp
	ApfsLib/DeviceSparseImage.h
	ApfsLib/DeviceWinFile.cpp
	ApfsLib/DeviceWinFile.h
	ApfsLib/DeviceWinPhys.cpp
	ApfsLib/DeviceWinPhys.h
	ApfsLib/DiskImageFile.cpp
	ApfsLib/DiskImageFile.h
	ApfsLib/DiskStruct.h
	ApfsLib/Endian.h
	ApfsLib/Global.h
	ApfsLib/GptPartitionMap.cpp
	ApfsLib/GptPartitionMap.h
	ApfsLib/KeyMgmt.cpp
	ApfsLib/KeyMgmt.h
	ApfsLib/LruCache.h
	ApfsLib/PList.cpp
	ApfsLib/PList.h
	ApfsLib/Util.cpp
	ApfsLib/Util.h
	ApfsLib/Unicode.cpp
	ApfsLib/Unicode.h)
find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)

target_include_directories(apfs PUBLIC "${ZLIB_INCLUDE_DIRS}" "${BZIP2_INCLUDE_DIR}")
target_link_libraries(apfs "${ZLIB_LIBRARIES}" "${BZIP2_LIBRARIES}" lzfse crypto)
target_compile_definitions(apfs PUBLIC _FILE_OFFSET_BITS=64 _DARWIN_USE_64_BIT_INODE)

add_executable(apfs-dump
	ApfsDump/Dumper.cpp
	ApfsDump/Dumper.h
	ApfsDump/Apfs.cpp)
target_link_libraries(apfs-dump apfs)

add_executable(apfs-dump-quick
	ApfsDumpQuick/ApfsDumpQuick.cpp)
target_link_libraries(apfs-dump-quick apfs)

add_executable(apfs-fuse
	apfsfuse/ApfsFuse.cpp
	apfsfuse/FuseMacCompat.cpp
	apfsfuse/FuseMacCompat.h)
target_compile_definitions(apfs-fuse PRIVATE _FILE_OFFSET_BITS=64 _DARWIN_USE_64_BIT_INODE)

find_package(PkgConfig QUIET)

if (APPLE)
	if (USE_FUSE3)
		find_path(MACOS_FUSE3_INCLUDE_DIR NAMES fuse3/fuse.h fuse3/fuse_lowlevel.h
			PATHS /usr/local/include /opt/homebrew/include)
		find_library(MACOS_FUSE3_LIBRARY NAMES fuse3 libfuse3
			PATHS /usr/local/lib /opt/homebrew/lib)
	endif()

	find_path(MACOS_FUSE2_INCLUDE_DIR NAMES fuse/fuse.h fuse/fuse_lowlevel.h
		PATHS
			/usr/local/include
			/usr/local/include/osxfuse
			/opt/homebrew/include
			"/Library/Application Support/fuse-t/include")
	find_library(MACOS_FUSE2_LIBRARY NAMES fuse fuse-t osxfuse
		PATHS
			/usr/local/lib
			/opt/homebrew/lib
			"/Library/Application Support/fuse-t/lib")

	if (USE_FUSE3 AND MACOS_FUSE3_INCLUDE_DIR AND MACOS_FUSE3_LIBRARY)
		message(STATUS "Found macOS FUSE 3: ${MACOS_FUSE3_LIBRARY}")
		target_include_directories(apfs-fuse PRIVATE "${MACOS_FUSE3_INCLUDE_DIR}" "${MACOS_FUSE3_INCLUDE_DIR}/fuse3")
		target_link_libraries(apfs-fuse apfs "${MACOS_FUSE3_LIBRARY}")
	elseif (MACOS_FUSE2_INCLUDE_DIR AND MACOS_FUSE2_LIBRARY)
		message(STATUS "Found macOS FUSE 2 / FUSE-T: ${MACOS_FUSE2_LIBRARY}")
		target_include_directories(apfs-fuse PRIVATE "${MACOS_FUSE2_INCLUDE_DIR}" "${MACOS_FUSE2_INCLUDE_DIR}/fuse")
		target_link_libraries(apfs-fuse apfs "${MACOS_FUSE2_LIBRARY}")
		target_compile_definitions(apfs-fuse PRIVATE USE_FUSE2)
	else()
		message(STATUS "Building apfs-fuse with dynamic macOS FUSE runtime loader (macFUSE / FUSE-T)")
		target_compile_definitions(apfs-fuse PRIVATE APFS_FUSE_DYNAMIC_MACOS=1)
		target_link_libraries(apfs-fuse apfs "${CMAKE_DL_LIBS}")
	endif()
else()
	if (USE_FUSE3)
		if (PkgConfig_FOUND)
			pkg_check_modules(FUSE3 QUIET fuse3)
		endif()
		if (FUSE3_FOUND)
			target_include_directories(apfs-fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
			target_link_libraries(apfs-fuse apfs ${FUSE3_LINK_LIBRARIES})
		else()
			target_link_libraries(apfs-fuse apfs fuse3 pthread dl)
		endif()
	else()
		if (PkgConfig_FOUND)
			pkg_check_modules(FUSE2 QUIET fuse)
		endif()
		if (FUSE2_FOUND)
			target_include_directories(apfs-fuse PRIVATE ${FUSE2_INCLUDE_DIRS})
			target_link_libraries(apfs-fuse apfs ${FUSE2_LINK_LIBRARIES})
		else()
			target_link_libraries(apfs-fuse apfs fuse pthread dl)
		endif()
		target_compile_definitions(apfs-fuse PRIVATE USE_FUSE2)
	endif()
endif()

add_executable(apfsutil ApfsUtil/ApfsUtil.cpp)
target_link_libraries(apfsutil apfs)

include(GNUInstallDirs)
install(TARGETS apfs-fuse apfsutil apfs-dump apfs-dump-quick RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(CODE "execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink apfs-fuse \"\$ENV{DESTDIR}${CMAKE_INSTALL_FULL_BINDIR}/mount.apfs\")")

set(CPACK_PACKAGE_NAME "apfs-wonder")
set(CPACK_PACKAGE_VENDOR "APFS-Wonder Contributors")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Next-Gen APFS FUSE Driver & Forensics Toolkit for Ubuntu and macOS Tahoe+")
set(CPACK_PACKAGE_VERSION_MAJOR 2)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_CONTACT "coldrazer@users.noreply.github.com")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "fuse3, libbz2-1.0, zlib1g, libc6")
set(CPACK_GENERATOR "TGZ;DEB")
include(CPack)
