/*
 * Kod serializacji i deserializacji nagłówka strony flash (page header) w formacie little-endian.
 * pagehdr_encode zapisuje pola struktury page_hdr_t do 64-bajtowego bufora (z wypełnieniem zerami pól zarezerwowanych),
 * a pagehdr_decode odczytuje pola z 64-bajtowego bufora do struktury page_hdr_t.
 */

#include "pagefmt.h"
#include <string.h>

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}
static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i] << (8 * i));
    return v;
}

void pagehdr_encode(uint8_t out[64], const page_hdr_t *h)
{
    memset(out, 0, 64);
    put_u32le(out + 0, h->magic);
    put_u32le(out + 4, h->version);
    put_u32le(out + 8, h->flags);
    put_u32le(out + 12, h->lba);
    put_u64le(out + 16, h->seq);
    put_u32le(out + 24, h->data_len);
    put_u32le(out + 28, h->crc32);
    /* 32..63 reserved = 0 */
}

int pagehdr_decode(page_hdr_t *h, const uint8_t in[64])
{
    if (!h || !in)
        return -1;
    h->magic = get_u32le(in + 0);
    h->version = get_u32le(in + 4);
    h->flags = get_u32le(in + 8);
    h->lba = get_u32le(in + 12);
    h->seq = get_u64le(in + 16);
    h->data_len = get_u32le(in + 24);
    h->crc32 = get_u32le(in + 28);
    return 0;
}
