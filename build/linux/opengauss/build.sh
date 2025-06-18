#!/bin/bash
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : dcf build for opengauss
#############################################################################

set -e

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help              show help information.
    -3rd|--binarylib_dir   the directory of third party binarylibs.
    -m|--version_mode      this values of paramenter is Debug, Release, the default value is Release.
    -t|--build_tool          this values of parameter is cmake, make, the default value is cmake.
"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -3rd|--binarylib_dir)
            if [ "$2"X = X ]; then
                echo "no given binarylib directory values"
                exit 1
            fi
            binarylib_dir=$2
            shift 2
            ;;
        -m|--version_mode)
          if [ "$2"X = X ]; then
              echo "no given version number values"
              exit 1
          fi
          version_mode=$2
          shift 2
          ;;
        -t|--build_tool)
          if [ "$2"X = X ]; then
              echo "no given build_tool values"
              exit 1
          fi
          build_tool=$2
          shift 2
          ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

if [ -z "${version_mode}" ] || [ "$version_mode"x == ""x ]; then
    version_mode=Release
fi
if [ -z "${binarylib_dir}" ]; then
    echo "ERROR: 3rd bin dir not set"
    exit 1
fi
if [ -z "${build_tool}" ] || [ "$build_tool"x == ""x ]; then
    build_tool=cmake
fi
if [ ! "$version_mode"x == "Debug"x ] && [ ! "$version_mode"x == "Release"x ]; then
    echo "ERROR: version_mode param is error"
    exit 1
fi
if [ ! "$build_tool"x == "make"x ] && [ ! "$build_tool"x == "cmake"x ]; then
    echo "ERROR: build_tool param is error"
    exit 1
fi

declare export_api=OFF

if [ "$test"x == ""x ]; then
    test=OFF
    export_api=ON
elif [ "$test"x == "ON"x ]; then
    export_api=OFF
elif [ "$test"x == "OFF"x ]; then
    export_api=OFF
fi

export CFLAGS="-std=gnu99"

LOCAL_PATH=${0}

CUR_PATH=$(pwd)

LOCAL_DIR=$(dirname "${LOCAL_PATH}")
export PACKAGE=$LOCAL_DIR/../../../
export OUT_PACKAGE=dcf

export DCF_LIBRARYS=$(pwd)/../../../library

[ -d "${DCF_LIBRARYS}" ] && rm -rf ${DCF_LIBRARYS}
mkdir -p $DCF_LIBRARYS/huawei_security
mkdir -p $DCF_LIBRARYS/openssl
mkdir -p $DCF_LIBRARYS/zstd
mkdir -p $DCF_LIBRARYS/cJSON

export LIB_PATH=$binarylib_dir/kernel/dependency/
export P_LIB_PATH=$binarylib_dir/kernel/platform/

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/lib     $DCF_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib                  $DCF_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zstd/lib                          $DCF_LIBRARYS/zstd/lib
cp -r $LIB_PATH/cjson/comm/lib                    $DCF_LIBRARYS/cJSON/lib

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/include    $DCF_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include              $DCF_LIBRARYS/openssl/include
cp -r $LIB_PATH/zstd/include                      $DCF_LIBRARYS/zstd/include
cp -r $LIB_PATH/cjson/comm/include/cjson          $DCF_LIBRARYS/cJSON/include

cd $PACKAGE
if [ "$build_tool"x == "cmake"x ];then
    cmake -DCMAKE_BUILD_TYPE=${version_mode} -DUSE32BIT=OFF -DTEST=${test} \
    -DENABLE_EXPORT_API=${export_api} CMakeLists.txt
    make all -sj 8
else
    make clean
    make BUILD_TYPE=${version_mode} -sj 8
fi

mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
cp src/interface/dcf_interface.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
cp output/lib/libdcf.* $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib