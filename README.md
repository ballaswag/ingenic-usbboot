# ingenic-usbboot
## Building

`make`

## Running
To see console output, a USB to TTL adapter is needed. For the Creality K1 board, the serial pinout is by the reset/boot botton.

To Enter USB Boot mode for the K1, hold the boot button, while holding boot hold down reset, let go reset then boot.

```$ sudo ./usbboot --uboot```

BIG caveat, I haven't gotten keyboard input to work through serial, I can only see the uboot logs. Please reach out if you figure out how to get keyboard input over serial for uboot.

## Unbricking Creality K1 Mainboard
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

## SPL/u-boot
The general idea is to write and execute loader codes at different memory spaces during the different stages of boot. SPL is a smaller piece of code that lives in TCSM/SRAM and executed to initialize DRAM. Then the bigger uboot code can be loaded and executed from DRAM.

The bootrom sets the stack pointer at 0xb2401000 (TCSM/SRAM), this is referenced as the `CONFIG_SPL_TEXT_BASE` in various Ingenic uboot configurations for the x2000 series. In USB mode, it allows reading and writing to memory regions over vendor defined requests (see usbboot source code for reference). The SPL in this repository has a specific format, the first 384 bytes define things such as cpu frequency, ddr frequency, uart port, and etc. This is important because the SPL code needs these to initialize the hardware. If this part is missing, the board will reboot when executing the SPL. The SPL code starts at 0xb2401800.

Once SPL completes, the DRAM is initialized. At this point, uboot can be loaded into DRAM and executed at 0x80100000, this is referenced `CONFIG_SYS_TEXT_BASE` in the u-boot configurations.


![k1 uboot](https://github.com/ballaswag/ingenic-usbboot/blob/main/uboot.png)
