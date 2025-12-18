/*
 * Implementacja obliczania sumy kontrolnej CRC32 (IEEE 802.3).
 * Kod inicjalizuje tablicę CRC przy pierwszym użyciu i udostępnia
 * funkcję crc32_ieee do wyliczania 32-bitowej sumy CRC dla bufora danych.
 */

#include "crc32.h"

static uint32_t crc_table[256];
static int crc_init_done = 0;

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
        {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    crc_init_done = 1;
}

uint32_t crc32_ieee(const void *data, size_t len)
{
    if (!crc_init_done)
        crc32_init();

    const unsigned char *p = (const unsigned char *)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
    {
        c = crc_table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}
