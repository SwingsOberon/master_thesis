#script with SPD=opteed flag removed from the arm-trusted-firmware build process, this allows the phone to start booting but it blocks on a login seems like... Also optee is not pointed to by the bootloader so it is certainly not available. The DEBUG=1 flag did not cause any problems in this case, if SPD=opteed is used the DEBUG=1 flag makes the RAM overflow.
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
  git clone https://github.com/ARM-software/arm-trusted-firmware/ -b v2.6
fi

cd arm-trusted-firmware
export CROSS_COMPILE=aarch64-linux-gnu-
make PLAT=sun50i_a64 DEBUG=1 bl31
export BL31=$(pwd)/build/sun50i_a64/debug/bl31.bin
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

#if u-boot directory doesn't exist, fetch it
if ! [[ -d "$(pwd)/u-boot" ]]
then
  git clone https://gitlab.com/pine64-org/u-boot.git -b pinephone-2021-06-22
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





