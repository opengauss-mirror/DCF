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
    -d|--test              this values of paramenter is ON, OFF, the default value is OFF.
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
        -d|--test)
          if [ "$2"X = X ]; then
              echo "no given version number values"
              exit 1
          fi
          test=$2
          shift 2
          ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

if [ "$version_mode"x == ""x ]; then
    version_mode=Release
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
PLAT_FORM_STR=$(sh get_platform_str.sh)
export PACKAGE=$LOCAL_DIR/../../../
export OUT_PACKAGE=dcf

export DCF_LIBRARYS=$(pwd)/../../../library

[ -d "${DCF_LIBRARYS}" ] && rm -rf ${DCF_LIBRARYS}
mkdir -p $DCF_LIBRARYS/huawei_security
mkdir -p $DCF_LIBRARYS/openssl
mkdir -p $DCF_LIBRARYS/lz4
mkdir -p $DCF_LIBRARYS/zstd
mkdir -p $DCF_LIBRARYS/cJSON

export LIB_PATH=$binarylib_dir/dependency/$PLAT_FORM_STR
export P_LIB_PATH=$binarylib_dir/platform/$PLAT_FORM_STR

cp -r $P_LIB_PATH/Huawei_Secure_C/Dynamic_Lib     $DCF_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib                  $DCF_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zstd/lib                          $DCF_LIBRARYS/zstd/lib
cp -r $LIB_PATH/lz4/comm/lib                      $DCF_LIBRARYS/lz4/lib
cp -r $LIB_PATH/cjson/comm/lib                    $DCF_LIBRARYS/cJSON/lib

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/include    $DCF_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include              $DCF_LIBRARYS/openssl/include
cp -r $LIB_PATH/zstd/include                      $DCF_LIBRARYS/zstd/include
cp -r $LIB_PATH/lz4/comm/include                  $DCF_LIBRARYS/lz4/include
cp -r $LIB_PATH/cjson/comm/include/cjson          $DCF_LIBRARYS/cJSON/include

cd $PACKAGE
cmake -DCMAKE_BUILD_TYPE=${version_mode} -DUSE32BIT=OFF -DTEST=${test} -DENABLE_EXPORT_API=${export_api} CMakeLists.txt
make all -sj

mkdir -p $binarylib_dir/component/${PLAT_FORM_STR}/${OUT_PACKAGE}/include
mkdir -p $binarylib_dir/component/${PLAT_FORM_STR}/${OUT_PACKAGE}/lib
cp src/interface/dcf_interface.h $binarylib_dir/component/${PLAT_FORM_STR}/${OUT_PACKAGE}/include
cp output/lib/libdcf.* $binarylib_dir/component/${PLAT_FORM_STR}/${OUT_PACKAGE}/lib