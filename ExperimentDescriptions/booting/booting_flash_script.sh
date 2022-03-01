#!/bin/bash
set -e #exit when any command fails
set -x #echo on

MOUNT=$1 #blockdevice /dev/sde for instance
SCRIPTDIR="$(dirname "$BASH_SOURCE")"
BUILDDIR=$(pwd)"/build_optee_pinephone"

sudo dd if=/dev/zero of=$MOUNT bs=1M count=1
sudo blockdev --rereadpt $MOUNT
cat <<EOT | sudo sfdisk $MOUNT
1G,32M,c
,,L
EOT
sudo dd if=$BUILDDIR/u-boot/u-boot-sunxi-with-spl.bin of=$MOUNT bs=1K seek=8
sudo mkfs.vfat ${MOUNT}1
sudo mkfs.ext4 ${MOUNT}2


sudo mount ${MOUNT}1 /mnt
cd /mnt
sudo cp $SCRIPTDIR/boot.cmd /mnt
sudo cp $BUILDDIR/sunxi64-linux/arch/arm64/boot/Image /mnt
sudo cp $BUILDDIR/sunxi64-linux/arch/arm64/boot/dts/allwinner/sun50i-a64-pinephone-1.2.dtb /mnt
sudo mkimage -C none -A arm64 -T script -d boot.cmd boot.scr
cd
sudo umount ${MOUNT}1


sudo mount ${MOUNT}2 /mnt
sudo cp -r $BUILDDIR/optee_client/out/export/usr /mnt
sudo cp -r $BUILDDIR/sunxi64-linux/modules/lib /mnt
sudo debootstrap --foreign --arch arm64 buster /mnt http://deb.debian.org/debian/
sudo cp /usr/bin/qemu-aarch64-static /mnt/usr/bin
cat <<EOT | sudo chroot /mnt /usr/bin/qemu-aarch64-static /bin/sh -i
/debootstrap/debootstrap --second-stage
exit
EOT
sudo umount ${MOUNT}2
