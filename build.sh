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
# Description  : build dcf
#############################################################################

set -e

DCF_DIR=$(cd "$1"; pwd)
BUILD_DIR="${DCF_DIR}/build/linux"

cd ${BUILD_DIR}
sh -x compile_opensource.sh
cd ${DCF_DIR}
cmake -D CMAKE_BUILD_TYPE=Release -DUSE32BIT=OFF -DUT=ON ./CMakeLists.txt
make clean
make all
