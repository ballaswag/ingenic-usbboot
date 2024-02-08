# Creality K1 (X2000E) usbboot tool
## Building

`make`

## Running
To see console output, a USB to TTL adapter is needed. For the Creality K1 board, the serial pinout is by the reset/boot botton.

To Enter USB Boot mode for the K1, hold the boot button, while holding boot hold down reset, let go reset then boot.

```$ sudo ./usbboot --uboot```

## Unbricking Creality K1 Mainboard (USE AT YOUR OWN RISK)
The Creality K1 comes with a set of backup partitions. The OTA partition stores either the string `ota:kernel` or `ota:kernel2` to indicate which set of partitions to boot. This tool allows you to quickly switch between the two. This should fix a bricked Creality K1 mainboard given the backup partitions are functional. For cases where the partition table, main, and backup partitions are corrupted, read through this [guide](https://github.com/ballaswag/k1-discovery/blob/main/k1-ingenic-cloner-instruction.pdf) for a better chance of recoverying the mainboad.

```
$ sudo ./usbboot --uboot
$ sudo ./usbboot --swap-ota
Current OTA points at kernel. Switching OTA to kernel2
Switched OTA to ota:kernel2

$ sudo ./usbboot --swap-ota
Current OTA points at kernel2. Switching OTA to kernel
Switched OTA to ota:kernel

```

## Dumping Partitions
Use this to dump your existing partitions in the K1. Example K1 partition table.
```
uboot(gpt/uboot):    Offset 0x000000000, Length 0x0000100000
ota:                 Offset 0x000100000, Length 0x0000100000
sn_mac:              Offset 0x000200000, Length 0x0000100000
rtos:                Offset 0x000300000, Length 0x0000400000
rtos2:               Offset 0x000700000, Length 0x0000400000
kernel:              Offset 0x000b00000, Length 0x0000800000
kernel2:             Offset 0x001300000, Length 0x0000800000
rootfs:              Offset 0x001b00000, Length 0x0012c00000
rootfs2:             Offset 0x014700000, Length 0x0012c00000
rootfs_data:         Offset 0x027300000, Length 0x0006400000
userdata:            Offset 0x02d700000, Length 0x01a4a00000

Total disk size:0x00000001d2104200, sectors:0x0000000000e90821
```

```
## start uboot
$ sudo ./usbboot --uboot

## dump the kernel partition to file ./kernel.out
$ sudo ./usbboot -o 0x000b00000 -s 0x0000800000 --dump-partition ./kernel.out
dumping parition at offset 0xb00000, size 0x800000
25.00% completed (1.00MB/s)
50.00% completed (1.00MB/s)
75.00% completed (1.00MB/s)
100.00% completed (1.00MB/s)

## dump the rootfs partition to ./rootfs.out
$ sudo ./usbboot -o 0x001b00000 -s 0x0012c00000 --dump-partition ./rootfs.out
dumping parition at offset 0x1b00000, size 0x12c00000
0.67% completed (0.67MB/s)
1.33% completed (1.00MB/s)
2.00% completed (1.00MB/s)
...
```

## SPL/u-boot
The general idea is to write and execute loader codes at different memory spaces during the different stages of boot. SPL is a smaller piece of code that lives in TCSM/SRAM and executed to initialize DRAM. Then the bigger uboot code can be loaded and executed from DRAM.  

The bootrom sets the stack pointer at 0xb2401000 (TCSM/SRAM), this is referenced as the `CONFIG_SPL_TEXT_BASE` in various Ingenic uboot configurations for the x2000 series. In USB mode, it allows reading and writing to memory regions over vendor defined requests (see usbboot source code for reference). The SPL in this repository has a specific format, the first 384 bytes define things such as cpu frequency, ddr frequency, uart port, and etc. This is important because the SPL code needs these to initialize the hardware. If this part is missing, the board will reboot when executing the SPL. The SPL code starts at 0xb2401800.  

Once SPL completes, the DRAM is initialized. At this point, uboot can be loaded into DRAM and executed at 0x80100000, this is referenced `CONFIG_SYS_TEXT_BASE` in the u-boot configurations.  

Also note that UARTs and such are also initialized via the SPL and not the uboot. If you're having issue where serial consoles are not working and pins are not behaving as you expect, make sure to check that the SPL is configured and builtin properly.

![k1 uboot](https://github.com/ballaswag/ingenic-usbboot/blob/main/uboot.png)
