#!/bin/bash
set -e #exit when any command fails
set -x #echo on

SCRIPTDIR="$(dirname "$BASH_SOURCE")"
BUILDDIR=$(pwd)"/build_optee_pinephone"

#if build directory doesn't exist, create it
if ! [[ -d $BUILDDIR ]]
then
  mkdir $BUILDDIR
fi

#go into the build directory
cd $BUILDDIR

#if arm-trusted-firmware directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/arm-trusted-firmware" ]]
then
  git clone https://github.com/crust-firmware/arm-trusted-firmware/ -b v2.4
fi

cd arm-trusted-firmware
export CROSS_COMPILE=aarch64-linux-gnu-
make PLAT=sun50i_a64 SPD=opteed bl31
export BL31=$(pwd)/build/sun50i_a64/release/bl31.bin
cd ..

#if optee_os directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/optee_os" ]]
then
  git clone https://github.com/OP-TEE/optee_os.git -b 3.16.0
fi

cd optee_os
make CFG_ARM64_CORE=y \ CFG_TEE_LOGLEVEL=4 \ CFG_TEE_CORE_LOG_LEVEL=4 \ CROSS_COMPILE32="ccache arm-linux-gnueabihf-" \ CROSS_COMPILE64="ccache aarch64-linux-gnu-" \ PLATFORM=sunxi-sun50i_a64
export TEE=$(pwd)/out/arm-plat-sunxi/core/tee-pager_v2.bin
cd ..

#if optee_client directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/optee_client" ]]
then
  git clone https://github.com/OP-TEE/optee_client -b 3.16.0
fi

cd optee_client
make
cd ..

#if crust directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/crust" ]]
then
  git clone https://github.com/crust-firmware/crust -b v0.5
fi

cd crust
export CROSS_COMPILE=or1k-linux-musl-
make pinephone_defconfig
make scp
export SCP=$(pwd)/build/scp/scp.bin
cd ..

#if u-boot directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/u-boot" ]]
then
  git clone https://gitlab.com/pine64-org/u-boot.git -b crust-2021-03-10
fi

cd u-boot
cp $SCRIPTDIR/mksunxi_fit_atf.sh $(pwd)/board/sunxi/mksunxi_fit_atf.sh
export CROSS_COMPILE=aarch64-linux-gnu-
make pinephone_defconfig
make
export PATH=$PATH:$(pwd)/tools/
cd ..

#if sunxi64-linux directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/sunxi64-linux" ]]
then
  git clone https://gitlab.com/mobian1/devices/sunxi64-linux.git -b v5.15
fi

cd sunxi64-linux
export ARCH=arm64
make menuconfig
#TODO: under Device Drivers -> Graphics support -> ARM devices one can find [ARM Mali Display Processor], set this to Module
cp $SCRIPTDIR/sun50i-a64-pinephone-1.2.dts $(pwd)/arch/arm/boot/dts/sun50i-a64-pinephone-1.2.dts
make defconfig
make Image
make dtbs
make modules
make INSTALL_MOD_PATH=modules modules modules_install





