#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct page_hdr
{
    uint32_t magic;
    uint32_t version;
    uint32_t flags; /* bit0: valid */
    uint32_t lba;
    uint64_t seq;
    uint32_t data_len; /* should be LBA_SIZE */
    uint32_t crc32;    /* of payload[0..data_len-1] */
} page_hdr_t;

#define PAGE_FLAG_VALID 0x1u

void pagehdr_encode(uint8_t out[64], const page_hdr_t *h);
int pagehdr_decode(page_hdr_t *h, const uint8_t in[64]);
