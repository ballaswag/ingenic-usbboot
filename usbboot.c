/***************************************************************************
 *             __________               __   ___.
 *   Open      \______   \ ____   ____ |  | _\_ |__   _______  ___
 *   Source     |       _//  _ \_/ ___\|  |/ /| __ \ /  _ \  \/  /
 *   Jukebox    |    |   (  <_> )  \___|    < | \_\ (  <_> > <  <
 *   Firmware   |____|_  /\____/ \___  >__|_ \|___  /\____/__/\_ \
 *                     \/            \/     \/    \/            \/
 * $Id$
 *
 * Copyright (C) 2021 Aidan MacDonald
 *
 * Directly adapted from jz4760_tools/usbboot.c,
 *   Copyright (C) 2015 by Amaury Pouly
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ****************************************************************************/

#include <libusb.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#define VR_GET_CPU_INFO     0
#define VR_SET_DATA_ADDRESS 1
#define VR_SET_DATA_LENGTH  2
#define VR_FLUSH_CACHES     3
#define VR_PROGRAM_START1   4
#define VR_PROGRAM_START2   5
#define VR_GET_ACK              0x10
#define VR_INIT                 0x11
#define VR_WRITE                0x12
#define VR_READ                 0x13
#define VR_UPDATE_CFG           0x14

#define MAGIC_DEBUG     ('D' << 24) | ('B' << 16) | ('G' << 8) | 0
#define MAGIC_MMC       ('M' << 24) | ('M' << 16) | ('C' << 8) | 0
#define MAGIC_POLICY    ('P' << 24) | ('O' << 16) | ('L' << 8) | ('I' << 0)

typedef struct ParameterInfo {
  uint32_t magic;
  uint32_t size;
  uint32_t data[0];
} ParameterInfo;

struct mmc_erase_range {
  uint32_t start;
  uint32_t end;
};

typedef struct mmc_param {
  int mmc_open_card;
  int mmc_erase;
  uint32_t mmc_erase_range_count;
  uint32_t blob[59]; // don't care, not formatting
} mmc_param;

typedef struct debug_param {
  uint32_t log_enabled;
  uint32_t transfer_data_chk;
  uint32_t write_back_chk;
  uint32_t transfer_size;
  uint32_t stage2_timeout;
} debug_param;

typedef struct policy_param {
  int use_nand_mgr;
  int use_nand_mtd;
  int use_mmc0;
  int use_mmc1;
  int use_mmc2;
  uint32_t use_sfc_nor;
  uint32_t use_sfc_nand;
  uint32_t use_spi_nand;
  uint32_t use_spi_nor;
  uint32_t offsets[32];
} policy_param;;


// burner commands
typedef struct update_cmd {
  uint32_t length;
  uint32_t unused[9]; // pad to 40 bytes
} UpdateCmd;

typedef struct write_cmd {
  uint64_t partition;
  uint32_t ops;
  uint32_t offset;
  uint32_t length;
  uint32_t crc;
  uint32_t unused[4];
} WriteCmd;

typedef struct read_cmd {
  uint64_t partition;
  uint32_t ops;
  uint32_t offset;
  uint32_t length;
  uint32_t unused[5];
} ReadCmd;


/* Global variables */
bool g_verbose = false;
libusb_device_handle* g_usb_dev = NULL;
int g_vid = 0, g_pid = 0;

/* Utility functions */
void die(const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void verbose(const char* msg, ...)
{
    if(!g_verbose)
        return;

    va_list ap;
    va_start(ap, msg);
    vprintf(msg, ap);
    printf("\n");
    va_end(ap);
}

void open_usb(void)
{
    if(g_usb_dev) {
        verbose("Closing USB device");
        libusb_close(g_usb_dev);
    }

    if(g_vid == 0 || g_pid == 0)
        die("Can't open USB device: vendor/product ID not specified");

    verbose("Opening USB device %04x:%04x", g_vid, g_pid);
    g_usb_dev = libusb_open_device_with_vid_pid(NULL, g_vid, g_pid);
    if(!g_usb_dev)
        die("Could not open USB device");

    int ret = libusb_claim_interface(g_usb_dev, 0);
    if(ret != 0) {
        libusb_close(g_usb_dev);
        die("Could not claim interface: %d", ret);
    }
}

void ensure_usb(void)
{
    if(!g_usb_dev)
        open_usb();
}

/* USB communication functions */
void jz_get_cpu_info(void)
{
    ensure_usb();
    verbose("Issue GET_CPU_INFO");

    uint8_t buf[9];
    int ret = libusb_control_transfer(g_usb_dev,
        LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
        VR_GET_CPU_INFO, 0, 0, buf, 8, 1000);
    if(ret != 0)
        die("Can't get CPU info: %d", ret);

    buf[8] = 0;
    printf("CPU info: %s\n", buf);
}

void jz_upload(const char* filename, int length)
{
    if(length < 0)
        die("invalid upload length: %d", length);

    ensure_usb();
    verbose("Transfer %d bytes from device to host", length);

    void* data = malloc(length);
    int xfered = 0;
    int ret = libusb_bulk_transfer(g_usb_dev, LIBUSB_ENDPOINT_IN | 1,
                                   data, length, &xfered, 10000);
    if(ret != 0)
        die("Transfer failed: %d", ret);
    if(xfered != length)
        die("Transfer error: got %d bytes, expected %d", xfered, length);

    FILE* f = fopen(filename, "wb");
    if(f == NULL)
        die("Can't open file '%s' for writing", filename);

    if(fwrite(data, length, 1, f) != 1)
        die("Error writing transfered data to file");

    fclose(f);
    free(data);
}

void bulk_transfer_out(void* data, int length) {
  verbose("Transfer %d bytes from host to device", length);
  int xfered = 0;
  int ret = libusb_bulk_transfer(g_usb_dev, LIBUSB_ENDPOINT_OUT | 1,
				 data, length, &xfered, 10000);
  if(ret != 0)
    die("Transfer failed: %d", ret);
  if(xfered != length)
    die("Transfer error: %d bytes recieved, expected %d", xfered, length);
}

#define jz_vendor_out_func(name, type, fmt) \
  void name(unsigned long param) {   \
        ensure_usb(); \
        verbose("Issue " #type fmt, param); \
        int ret = libusb_control_transfer(g_usb_dev, \
            LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE, \
            VR_##type, param >> 16, param & 0xffff, NULL, 0, 1000); \
        if(ret != 0) \
            die("Request " #type " failed: %d", ret); \
    }

jz_vendor_out_func(jz_set_data_address, SET_DATA_ADDRESS, " 0x%08lx")
jz_vendor_out_func(jz_set_data_length, SET_DATA_LENGTH, " 0x%0lx")
jz_vendor_out_func(_jz_flush_caches, FLUSH_CACHES, "")
jz_vendor_out_func(jz_program_start1, PROGRAM_START1, " 0x%08lx")
jz_vendor_out_func(jz_program_start2, PROGRAM_START2, " 0x%08lx")
jz_vendor_out_func(jz_init, INIT, " 0x%08lx")  
#define jz_flush_caches() _jz_flush_caches(0)

void jz_generic_out(uint8_t op,
		    unsigned long param,
		    unsigned char *data,
		    uint16_t len) {
  ensure_usb();
  verbose("Issue 0x%x", op);
  int ret = libusb_control_transfer(g_usb_dev,
				    LIBUSB_ENDPOINT_OUT|LIBUSB_REQUEST_TYPE_VENDOR|LIBUSB_RECIPIENT_DEVICE,
				    op, param >> 16, param & 0xffff, data, len, 1000);
  if(ret != len)					     
    die("Request 0x%x failed, only transfered: %d", op, ret);
}

void jz_download(const char* filename)
{
    FILE* f = fopen(filename, "rb");
    if(f == NULL)
        die("Can't open file '%s' for reading", filename);

    fseek(f, 0, SEEK_END);
    int length = ftell(f);
    fseek(f, 0, SEEK_SET);

    void* data = malloc(length);
    if(fread(data, length, 1, f) != 1)
        die("Error reading data from file");
    fclose(f);

    jz_set_data_length(length);
    bulk_transfer_out(data, length);

    free(data);
}

void jz_get_ack() {
  ensure_usb();
  verbose("Issue VR_GET_ACK");
  
  uint8_t buf[4];
  int ret = libusb_control_transfer(g_usb_dev,
        LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_RECIPIENT_DEVICE,
        VR_GET_ACK, 0, 0, buf, 4, 1000);
  if(ret != 4)
    die("Can't get ACK: %d", ret);
}

void enable_mmc() {
  ensure_usb();

  ParameterInfo *policy_param_info = (ParameterInfo*) malloc(sizeof(ParameterInfo) + sizeof(policy_param));
  policy_param_info->magic = MAGIC_POLICY;
  policy_param_info->size = sizeof(policy_param);
  memset(policy_param_info->data, 0, sizeof(policy_param));
  policy_param *policy_cfg = (policy_param*)policy_param_info->data;
  policy_cfg->use_mmc0 = 1;

  ParameterInfo *dbg_param_info = (ParameterInfo*) malloc(sizeof(ParameterInfo) + sizeof(debug_param));
  dbg_param_info->magic = MAGIC_DEBUG;
  dbg_param_info->size = sizeof(debug_param);
  debug_param *dbg = (debug_param*)dbg_param_info->data;
  dbg->log_enabled = 1;
  dbg->transfer_data_chk = 0;
  dbg->write_back_chk = 0;
  dbg->transfer_size = 0;
  dbg->stage2_timeout = 0;

  ParameterInfo *mmc_param_info = (ParameterInfo*) malloc(sizeof(ParameterInfo) + sizeof(mmc_param));
  mmc_param_info->magic = MAGIC_MMC;
  mmc_param_info->size = sizeof(mmc_param);
  memset(mmc_param_info->data, 0, sizeof(mmc_param));

  uint32_t data_size = 3 * 8 + policy_param_info->size + dbg_param_info->size + mmc_param_info->size;
  unsigned char data[data_size];
  unsigned char *p = data;
  uint32_t offset = 0;
  memcpy(p + offset, dbg_param_info, 4 + 4 + dbg_param_info->size);
  offset += 4 + 4 + dbg_param_info->size;
  memcpy(p + offset, mmc_param_info, 4 + 4 + mmc_param_info->size);
  offset += 4 + 4 + mmc_param_info->size;
  memcpy(p + offset, policy_param_info, 4 + 4 + policy_param_info->size);

  UpdateCmd *update = (UpdateCmd*) malloc(sizeof(UpdateCmd));
  memset(update, 0, sizeof(UpdateCmd));
  update->length = data_size;

  jz_generic_out(VR_UPDATE_CFG, 0, (unsigned char*)update, sizeof(UpdateCmd));

  bulk_transfer_out(p, data_size);

  free(policy_param_info);
  free(dbg_param_info);
  free(mmc_param_info);
  free(update);
  
  jz_get_ack();
  jz_init(0);
  jz_get_ack();
}

void mmc_read(uint32_t offset, uint32_t length, unsigned char* out) {
  ReadCmd *read = (ReadCmd*) malloc(sizeof(ReadCmd));
  memset(read, 0, sizeof(ReadCmd));
  read->ops = 0x020000; // mmc
  read->offset = offset;
  read->length = length;
  
  jz_generic_out(VR_READ, 0, (unsigned char*)read, sizeof(ReadCmd));
  free(read);

  while (1) {
    int xfered = 0;
    int ret = libusb_bulk_transfer(g_usb_dev, LIBUSB_ENDPOINT_IN | 1,
			       out, length, &xfered, 10000);
    if(ret != 0)
      die("OTA read failed: %d", ret);

    if(xfered == length)
      break;
  }
}

void mmc_read_partition(uint32_t offset, uint32_t length, const char* fname) {
  enable_mmc();
  if(length == 0)
    die("invalid partition length: %d", length);

  printf("dumping parition at offset 0x%x, size 0x%x\n", offset, length);

  uint32_t chunk_size = 1024 * 1024 * 2; // 2mb
  unsigned char chunk[chunk_size];

  FILE* f = fopen(fname, "wb");
  if(f == NULL)
    die("Can't open file '%s' for writing", fname);
  
  uint32_t cursor = offset;
  uint32_t end = offset + length;
  while (cursor < end) {
    uint32_t read_size = (end - cursor) >= chunk_size
      ? chunk_size
      : (end - cursor);

    uint32_t start = (uint32_t)time(NULL);
    mmc_read(cursor, read_size, chunk);
    uint32_t duration = (uint32_t)time(NULL) - start;

    cursor += read_size;

    printf("%.2f%% completed (%.2fMB/s)\n",
	   (cursor - offset) / (float)length * 100,
	   (read_size / 1024 / 1024) / (float)duration);

    if (fwrite(chunk, read_size, 1, f) != 1)
      die("Failed to write data to %x", fname);
  }

  fclose(f);
}

void mmc_write(uint32_t offset, uint32_t length, unsigned char* in) {
  WriteCmd *write = (WriteCmd*) malloc(sizeof(WriteCmd));
  memset(write, 0, sizeof(WriteCmd));
  write->ops = 0x020000; // mmc
  write->offset = offset;
  write->length = length;

  jz_generic_out(VR_WRITE, 0, (unsigned char*)write, sizeof(WriteCmd));
  free(write);

  bulk_transfer_out(in, length);
}

void swap_ota_partition(bool force) {
  ensure_usb();
  enable_mmc();

  uint32_t ota_len = 512;
  unsigned char ota[ota_len];

  mmc_read(0x100000, ota_len, ota);

  char ota_in[ota_len];
  memset(ota_in, 0, ota_len);
  
  if (strncmp((char*)ota, "ota:kernel2", 11) == 0) {
    printf("Current OTA points at kernel2. Switching OTA to kernel\n");
    strcpy(ota_in, "ota:kernel\n\n");
  } else if (strncmp((char*)ota, "ota:kernel\n", 11) == 0) {
    printf("Current OTA points at kernel. Switching OTA to kernel2\n");
    strcpy(ota_in, "ota:kernel2\n\n");
  } else {
    if (!force) {
      die("Exiting! Your OTA contains unexpected values, swapping OTA might not fix your issue.");
    }

    printf("Unknown value in OTA. Forcing OTA to use ota:kernel\n");
    strcpy(ota_in, "ota:kernel\n\n");
  }

  mmc_write(0x100000, ota_len, (unsigned char*)ota_in);
  printf("Switched OTA to %s", ota_in);
}

/* Default settings */
struct cpu_profile {
    const char* name;
    int vid, pid;
    unsigned long s1_load_addr, s1_exec_addr;
    unsigned long s2_load_addr, s2_exec_addr;
};

static const struct cpu_profile cpu_profiles[] = {
    {"x2000",
     0xa108, 0xeaef,
     0xb2401000, 0xb2401800,
     0x80100000, 0x80100000},
    {NULL}
};

/* Simple "download and run" functions for dev purposes */
unsigned long s1_load_addr = 0, s1_exec_addr = 0;
unsigned long s2_load_addr = 0, s2_exec_addr = 0;

void apply_cpu_profile(const char* name)
{
    const struct cpu_profile* p = &cpu_profiles[0];
    for(p = &cpu_profiles[0]; p->name != NULL; ++p) {
        if(strcmp(p->name, name) != 0)
            continue;

        g_vid = p->vid;
        g_pid = p->pid;
        s1_load_addr = p->s1_load_addr;
        s1_exec_addr = p->s1_exec_addr;
        s2_load_addr = p->s2_load_addr;
        s2_exec_addr = p->s2_exec_addr;
        return;
    }

    die("CPU '%s' not known", name);
}

void run_stage1(const char* filename)
{
    if(s1_load_addr == 0 || s1_exec_addr == 0)
        die("No stage1 binary settings -- did you specify --cpu?");
    jz_set_data_address(s1_load_addr);
    jz_download(filename);
    jz_program_start1(s1_exec_addr);
}

void run_stage2(const char* filename)
{
    if(s2_load_addr == 0 || s2_exec_addr == 0)
        die("No stage2 binary settings -- did you specify --cpu?");
    jz_set_data_address(s2_load_addr);
    jz_download(filename);
    jz_flush_caches();
    jz_program_start2(s2_exec_addr);
}

void start_x2000_uboot() {
  run_stage1("./spl.bin");
  sleep(1);
  run_stage2("./uboot.bin");
}

/* Main functions */
void usage()
{
    printf("\
Usage: usbboot [options]\n\
\n\
Basic options:\n\
  --uboot            Start uboot\n\
  --cpu <cpu>        Select device CPU type\n\
  --stage1 <file>    Download and execute stage1 binary\n\
  --stage2 <file>    Download and execute stage2 binary\n\
\n\
Advanced options:\n\
  --vid <vid>        Specify USB vendor ID\n\
  --pid <pid>        Specify USB product ID\n\
  --swap-ota         Switch OTA between kernel/kernel2\n\
  --force-swap-ota   Ignore unknown OTA value, write ota:kernel to OTA\n\
  --cpuinfo          Ask device for CPU info\n\
  --addr <addr>      Set data address\n\
  --length <len>     Set data length\n\
  --upload <file>    Transfer data from device (needs prior --length)\n\
  --download <file>  Transfer data to device\n\
  --start1 <addr>    Execute stage1 code at address\n\
  --start2 <addr>    Execute stage2 code at address\n\
  --flush-caches     Flush device CPU caches\n\
  --renumerate       Close and re-open the USB device\n\
  --wait <time>      Wait for <time> seconds\n\
  -v, --verbose      Be verbose\n\
\n\
Known CPU types and default stage1/stage2 binary settings:\n");
    const struct cpu_profile* p = &cpu_profiles[0];
    for(p = &cpu_profiles[0]; p->name != NULL; ++p) {
        printf("* %s\n", p->name);
        printf("  - USB ID: %04x:%04x\n", p->vid, p->pid);
        printf("  - Stage1: load %#08lx, exec %#08lx\n",
               p->s1_load_addr, p->s1_exec_addr);
        printf("  - Stage2: load %#08lx, exec %#08lx\n",
               p->s2_load_addr, p->s2_exec_addr);
    }

    exit(1);
}

void cleanup()
{
    if(g_usb_dev == NULL)
        libusb_close(g_usb_dev);
    libusb_exit(NULL);
}

int main(int argc, char* argv[])
{
    if(argc <= 1)
        usage();

    libusb_init(NULL);
    atexit(cleanup);

    apply_cpu_profile("x2000");

    enum {
        OPT_VID = 0x100, OPT_PID,
        OPT_CPUINFO,
        OPT_START1, OPT_START2, OPT_FLUSH_CACHES,
        OPT_RENUMERATE, OPT_WAIT, OPT_SWAP_OTA,
	OPT_FORCE_SWAP_OTA, OPT_DUMP_PARITION
    };

    static const struct option long_options[] = {
        {"uboot", no_argument, 0, 'b'},      
        {"cpu", required_argument, 0, 'c'},
        {"stage1", required_argument, 0, '1'},
        {"stage2", required_argument, 0, '2'},
        {"vid", required_argument, 0, OPT_VID},
        {"pid", required_argument, 0, OPT_PID},
        {"cpuinfo", no_argument, 0, OPT_CPUINFO},
        {"addr", required_argument, 0, 'a'},
        {"length", required_argument, 0, 'l'},
        {"partition-size", required_argument, 0, 's'},
        {"partition-offset", required_argument, 0, 'o'},
        {"upload", required_argument, 0, 'u'},
        {"download", required_argument, 0, 'd'},
        {"start1", required_argument, 0, OPT_START1},
        {"start2", required_argument, 0, OPT_START2},
        {"flush-caches", no_argument, 0, OPT_FLUSH_CACHES},
        {"renumerate", no_argument, 0, OPT_RENUMERATE},
        {"wait", required_argument, 0, OPT_WAIT},
        {"swap-ota", no_argument, 0, OPT_SWAP_OTA},
        {"force-swap-ota", no_argument, 0, OPT_FORCE_SWAP_OTA},
        {"dump-partition", required_argument, 0, OPT_DUMP_PARITION},	
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int data_length = -1;
    uint32_t partition_offset = 0;
    uint32_t partition_size = 0;
    while((opt = getopt_long(argc, argv, "bhvc:1:2:a:l:s:o:u:d:", long_options, NULL)) != -1) {
        unsigned long param;
        char* end;
        switch(opt) {
        case OPT_VID:
        case OPT_PID:
        case 'a':
        case 'l':
        case OPT_START1:
        case OPT_START2:
        case OPT_WAIT:
            param = strtoul(optarg, &end, 0);
            if(*end)
                die("Invalid argument '%s'", optarg);

            break;
	case 's':
            partition_size = strtoul(optarg, &end, 0);
            if(*end)
                die("Invalid argument '%s'", optarg);
	    break;
        case 'o':
            partition_offset = strtoul(optarg, &end, 0);
            if(*end)
                die("Invalid argument '%s'", optarg);
	    break;
        default:
            break;
        }

        switch(opt) {
	case 'b':
	    start_x2000_uboot();
	    break;
        case 'h':
            usage();
            break;
        case 'v':
            g_verbose = true;
            break;
        case 'c':
            apply_cpu_profile(optarg);
            break;
        case '1':
            run_stage1(optarg);
            break;
        case '2':
            run_stage2(optarg);
            break;
        case OPT_VID:
            g_vid = param & 0xffff;
            break;
        case OPT_PID:
            g_pid = param & 0xffff;
            break;
        case OPT_CPUINFO:
            jz_get_cpu_info();
            break;
        case 'a':
            jz_set_data_address(param);
            break;
        case 'l':
            data_length = param;
            jz_set_data_length(param);
            break;
        case 'u':
            if(data_length < 0)
                die("Need to specify --length before --upload");
            jz_upload(optarg, data_length);
            break;
        case 'd':
            jz_download(optarg);
            break;
        case OPT_START1:
            jz_program_start1(param);
            break;
        case OPT_START2:
            jz_program_start2(param);
            break;
        case OPT_FLUSH_CACHES:
            jz_flush_caches();
            break;
        case OPT_RENUMERATE:
            open_usb();
            break;
        case OPT_WAIT:
            verbose("Wait %lu seconds", param);
            sleep(param);
            break;
        case OPT_SWAP_OTA:
            verbose("Swapping OTA between kernel/kernel2");
	    swap_ota_partition(false);
            break;
        case OPT_FORCE_SWAP_OTA:
            verbose("Force OTA to boot ota:kernel");
	    swap_ota_partition(true);
            break;
        case OPT_DUMP_PARITION:
	    if (partition_size <= 0)
	      die("must provide a positive partition length with option --partition-size");

            verbose("Dump a partition to file");
	    mmc_read_partition(partition_offset, partition_size, optarg);
            break;
	case 'o':
	case 's':
	  break;
        default:
            /* should only happen due to a bug */
	    die("Bad option");
	    break;
        }
    }

    if(optind != argc)
        die("Extra arguments on command line");

    return 0;
}
