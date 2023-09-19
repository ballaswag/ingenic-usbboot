# ingenic-usbboot
## Building

`make`

## Running
To see console output, a USB to TTL adapter is needed. For the Creality K1 board, the serial pinout is by the reset/boot botton.

To Enter USB Boot mode for the K1, hold the boot button, while holding boot hold down reset, let go reset then boot.

```./usbboot --cpu x2000 --stage1 ./spl.bin --wait 1 --stage2 ./uboot.bin```


BIG caveat, I haven't gotten keyboard input to work through serial, I can only see the uboot logs. Please reach out if you figure out how to get keyboard input over serial for uboot.


## SPL/u-boot
The general idea is to write and execute loader codes at different memory spaces during the different stages of boot. SPL is a smaller piece of code that lives in TCSM/SRAM and executed to initialize DRAM. Then the bigger uboot code can be loaded and executed from DRAM.

The bootrom sets the stack pointer at 0xb2401000 (TCSM/SRAM), this is referenced as the `CONFIG_SPL_TEXT_BASE` in various Ingenic uboot configurations for the x2000 series. In USB mode, it allows reading and writing to memory regions over vendor defined requests (see usbboot source code for reference). The SPL in this repository has a specific format, the first 384 bytes define things such as cpu frequency, ddr frequency, uart port, and etc. This is important because the SPL code needs these to initialize the hardware. If this part is missing, the board will reboot when executing the SPL. The SPL code starts at 0xb2401800.

Once SPL completes, the DRAM is initialized. At this point, uboot can be loaded into DRAM and executed at 0x80100000, this is referenced `CONFIG_SYS_TEXT_BASE` in the u-boot configurations.


![k1 uboot](https://github.com/ballaswag/ingenic-usbboot/blob/main/uboot.png)
