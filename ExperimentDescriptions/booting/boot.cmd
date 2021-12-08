fatload mmc 0 0x46000000 Image
fatload mmc 0 0x49000000 sun50i-a64-pinephone-1.2.dtb

setenv bootargs console=ttyS0,115200 console=tty1 earlyprintk root=/dev/mmcblk0p2 rootwait panic=10

booti 0x46000000 - 0x49000000
