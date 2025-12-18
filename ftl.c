/*
 * Implementacja prostego Flash Translation Layer (FTL) typu log-structured na emulowanej pamięci flash.
 * Kod utrzymuje mapowanie LBA->PBA z numerem sekwencji, skanuje flash przy starcie w celu odbudowy stanu,
 * zapisuje dane do nowych stron z nagłówkiem i CRC32 związanym z polami nagłówka oraz payloadem,
 * odczytuje dane na podstawie mapowania, oznacza stare strony jako nieżywe oraz wykonuje prosty GC
 * (czyszczenie stron used=1, live=0). Zawiera też helpery do snapshotu mapowania i walidacji stron.
 */

#include "ftl.h"
#include "ftl_config.h"
#include "pagefmt.h"
#include "crc32.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

struct ftl
{
    flash_t flash;

    uint32_t lba_to_pba[NUM_LBAS];
    uint64_t lba_to_seq[NUM_LBAS];

    uint8_t page_used[NUM_PAGES];
    uint8_t page_live[NUM_PAGES];
    uint32_t alloc_cursor;
    uint32_t gc_cursor;

    uint64_t global_seq;
};

static void recompute_live(ftl_t *f)
{
    memset(f->page_live, 0, sizeof(f->page_live));
    for (uint32_t l = 0; l < NUM_LBAS; l++)
    {
        uint32_t p = f->lba_to_pba[l];
        if (p != INVALID_PBA && p < NUM_PAGES)
            f->page_live[p] = 1;
    }
}

static int is_free_page(const uint8_t *pagebuf)
{
    page_hdr_t h;
    if (pagehdr_decode(&h, pagebuf) != 0)
        return 1;
    if (h.magic != FLASH_MAGIC_PAGE)
        return 1;
    if ((h.flags & PAGE_FLAG_VALID) == 0)
        return 1;
    return 0;
}

static void put_u32le_local(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void put_u64le_local(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint32_t page_crc32_bound(uint32_t lba, uint64_t seq, uint32_t data_len, const uint8_t *payload)
{
    uint8_t tmp[16u + LBA_SIZE];

    put_u32le_local(tmp + 0, lba);
    put_u64le_local(tmp + 4, seq);
    put_u32le_local(tmp + 12, data_len);

    if (data_len > 0 && payload)
        memcpy(tmp + 16, payload, data_len);

    return crc32_ieee(tmp, 16u + data_len);
}

static int scan_flash_build_state(ftl_t *f)
{
    for (uint32_t l = 0; l < NUM_LBAS; l++)
    {
        f->lba_to_pba[l] = INVALID_PBA;
        f->lba_to_seq[l] = 0;
    }
    memset(f->page_used, 0, sizeof(f->page_used));
    memset(f->page_live, 0, sizeof(f->page_live));
    f->global_seq = 0;

    uint8_t *page = (uint8_t *)malloc(PAGE_SIZE);
    if (!page)
        return -ENOMEM;

    for (uint32_t p = 0; p < NUM_PAGES; p++)
    {
        int rc = flash_read_page(&f->flash, p, page, PAGE_SIZE);
        if (rc != 0)
        {
            free(page);
            return rc;
        }

        if (is_free_page(page))
            continue;

        page_hdr_t h;
        pagehdr_decode(&h, page);

        if (h.magic != FLASH_MAGIC_PAGE || h.version != FLASH_PAGE_VERSION)
            continue;
        if ((h.flags & PAGE_FLAG_VALID) == 0)
            continue;
        if (h.lba >= NUM_LBAS)
            continue;
        if (h.data_len != LBA_SIZE)
            continue;

        const uint8_t *payload = page + HEADER_SIZE;

        /* bound CRC */
        uint32_t c = page_crc32_bound(h.lba, h.seq, h.data_len, payload);
        if (c != h.crc32)
            continue;

        f->page_used[p] = 1;
        if (h.seq > f->global_seq)
            f->global_seq = h.seq;

        if (h.seq > f->lba_to_seq[h.lba])
        {
            f->lba_to_seq[h.lba] = h.seq;
            f->lba_to_pba[h.lba] = p;
        }
    }

    recompute_live(f);
    free(page);
    return 0;
}

static int gc_one(ftl_t *f)
{
    /* znajdź stale page (used=1, live=0) i wymaż */
    for (uint32_t i = 0; i < NUM_PAGES; i++)
    {
        uint32_t p = (f->gc_cursor + i) % NUM_PAGES;
        if (f->page_used[p] && !f->page_live[p])
        {
            int rc = flash_erase_page(&f->flash, p);
            if (rc != 0)
                return rc;
            f->page_used[p] = 0;
            f->page_live[p] = 0;
            f->gc_cursor = (p + 1) % NUM_PAGES;
            return 0;
        }
    }
    return -ENOSPC; /* brak stron do odzyskania */
}

static int alloc_page(ftl_t *f, uint32_t *out_pba)
{
    if (!out_pba)
        return -EINVAL;

    for (uint32_t i = 0; i < NUM_PAGES; i++)
    {
        uint32_t p = (f->alloc_cursor + i) % NUM_PAGES;
        if (!f->page_used[p])
        {
            *out_pba = p;
            f->alloc_cursor = (p + 1) % NUM_PAGES;
            return 0;
        }
    }

    int rc = gc_one(f);
    if (rc != 0)
        return rc;

    for (uint32_t i = 0; i < NUM_PAGES; i++)
    {
        uint32_t p = (f->alloc_cursor + i) % NUM_PAGES;
        if (!f->page_used[p])
        {
            *out_pba = p;
            f->alloc_cursor = (p + 1) % NUM_PAGES;
            return 0;
        }
    }
    return -ENOSPC;
}

int ftl_open(ftl_t **out, const char *flash_path, int create_fresh)
{
    if (!out || !flash_path)
        return -EINVAL;
    *out = NULL;

    ftl_t *f = (ftl_t *)calloc(1, sizeof(*f));
    if (!f)
        return -ENOMEM;

    int rc = flash_open(&f->flash, flash_path, PAGE_SIZE, NUM_PAGES, create_fresh);
    if (rc != 0)
    {
        free(f);
        return rc;
    }

    f->alloc_cursor = 0;
    f->gc_cursor = 0;

    rc = scan_flash_build_state(f);
    if (rc != 0)
    {
        flash_close(&f->flash);
        free(f);
        return rc;
    }

    *out = f;
    return 0;
}

int ftl_close(ftl_t *f)
{
    if (!f)
        return -EINVAL;
    flash_close(&f->flash);
    free(f);
    return 0;
}

int ftl_write(ftl_t *f, uint32_t lba, const void *buf, uint32_t nblocks)
{
    if (!f || (!buf && nblocks))
        return -EINVAL;
    if (nblocks == 0)
        return 0;
    if (lba >= NUM_LBAS)
        return -ERANGE;
    if (lba + nblocks > NUM_LBAS)
        return -ERANGE;

    const uint8_t *in = (const uint8_t *)buf;

    uint8_t *page = (uint8_t *)calloc(1, PAGE_SIZE);
    if (!page)
        return -ENOMEM;

    int rc = 0;
    for (uint32_t i = 0; i < nblocks; i++)
    {
        uint32_t cur_lba = lba + i;

        uint32_t new_pba = INVALID_PBA;
        rc = alloc_page(f, &new_pba);
        if (rc != 0)
            break;

        memcpy(page + HEADER_SIZE, in + (size_t)i * LBA_SIZE, LBA_SIZE);

        page_hdr_t h;
        memset(&h, 0, sizeof(h));
        h.magic = FLASH_MAGIC_PAGE;
        h.version = FLASH_PAGE_VERSION;
        h.flags = PAGE_FLAG_VALID;
        h.lba = cur_lba;
        h.seq = ++f->global_seq;
        h.data_len = LBA_SIZE;

        h.crc32 = page_crc32_bound(h.lba, h.seq, h.data_len, page + HEADER_SIZE);

        pagehdr_encode(page, &h);

        rc = flash_write_page(&f->flash, new_pba, page, PAGE_SIZE);
        if (rc != 0)
            break;

        uint32_t old_pba = f->lba_to_pba[cur_lba];

        f->lba_to_pba[cur_lba] = new_pba;
        f->lba_to_seq[cur_lba] = h.seq;

        f->page_used[new_pba] = 1;
        f->page_live[new_pba] = 1;

        if (old_pba != INVALID_PBA && old_pba < NUM_PAGES)
            f->page_live[old_pba] = 0;
    }

    free(page);
    (void)flash_fsync(&f->flash);
    return rc;
}

int ftl_read(ftl_t *f, uint32_t lba, void *buf, uint32_t nblocks)
{
    if (!f || (!buf && nblocks))
        return -EINVAL;
    if (nblocks == 0)
        return 0;
    if (lba >= NUM_LBAS)
        return -ERANGE;
    if (lba + nblocks > NUM_LBAS)
        return -ERANGE;

    uint8_t *out = (uint8_t *)buf;
    uint8_t *page = (uint8_t *)malloc(PAGE_SIZE);
    if (!page)
        return -ENOMEM;

    int any_missing = 0;

    for (uint32_t i = 0; i < nblocks; i++)
    {
        uint32_t cur_lba = lba + i;
        uint32_t pba = f->lba_to_pba[cur_lba];
        uint64_t seq = f->lba_to_seq[cur_lba];

        uint8_t *dst = out + (size_t)i * LBA_SIZE;
        memset(dst, 0, LBA_SIZE);

        if (pba == INVALID_PBA)
        {
            any_missing = 1;
            continue;
        }

        int rc = flash_read_page(&f->flash, pba, page, PAGE_SIZE);
        if (rc != 0)
        {
            any_missing = 1;
            continue;
        }

        page_hdr_t h;
        pagehdr_decode(&h, page);

        if (h.magic != FLASH_MAGIC_PAGE ||
            (h.flags & PAGE_FLAG_VALID) == 0 ||
            h.version != FLASH_PAGE_VERSION ||
            h.lba != cur_lba ||
            h.seq != seq ||
            h.data_len != LBA_SIZE)
        {
            any_missing = 1;
            continue;
        }

        const uint8_t *payload = page + HEADER_SIZE;

        uint32_t c = page_crc32_bound(h.lba, h.seq, h.data_len, payload);
        if (c != h.crc32)
        {
            any_missing = 1;
            continue;
        }

        memcpy(dst, payload, LBA_SIZE);
    }

    free(page);
    return any_missing ? -EIO : 0;
}

void ftl_dump_map(const ftl_t *f)
{
    if (!f)
        return;
    printf("LBA -> PBA (seq)\n");
    for (uint32_t l = 0; l < NUM_LBAS; l++)
    {
        if (f->lba_to_pba[l] == INVALID_PBA)
        {
            printf("%3u -> (unmapped)\n", l);
        }
        else
        {
            printf("%3u -> %3u (seq=%llu)\n", l, f->lba_to_pba[l], (unsigned long long)f->lba_to_seq[l]);
        }
    }
}

/* Snapshot helpers */

uint32_t ftl_num_lbas(const ftl_t *f)
{
    (void)f;
    return NUM_LBAS;
}

int ftl_get_mapping(const ftl_t *f, uint32_t lba, uint32_t *pba, uint64_t *seq)
{
    if (!f || !pba || !seq)
        return -EINVAL;
    if (lba >= NUM_LBAS)
        return -ERANGE;
    *pba = f->lba_to_pba[lba];
    *seq = f->lba_to_seq[lba];
    return 0;
}

int ftl_apply_mapping(ftl_t *f, const uint32_t *pba, const uint64_t *seq)
{
    if (!f || !pba || !seq)
        return -EINVAL;
    for (uint32_t l = 0; l < NUM_LBAS; l++)
    {
        f->lba_to_pba[l] = pba[l];
        f->lba_to_seq[l] = seq[l];
    }
    recompute_live(f);
    return 0;
}

int ftl_get_page_crc_for_lba(const ftl_t *f, uint32_t pba, uint32_t expect_lba, uint64_t expect_seq, uint32_t *out_crc32)
{
    if (!f || !out_crc32)
        return -EINVAL;
    if (pba >= NUM_PAGES)
        return -ERANGE;

    uint8_t *page = (uint8_t *)malloc(PAGE_SIZE);
    if (!page)
        return -ENOMEM;

    int rc = flash_read_page(&f->flash, pba, page, PAGE_SIZE);
    if (rc != 0)
    {
        free(page);
        return rc;
    }

    page_hdr_t h;
    pagehdr_decode(&h, page);

    if (h.magic != FLASH_MAGIC_PAGE ||
        (h.flags & PAGE_FLAG_VALID) == 0 ||
        h.version != FLASH_PAGE_VERSION ||
        h.lba != expect_lba ||
        h.seq != expect_seq ||
        h.data_len != LBA_SIZE)
    {
        free(page);
        return -EIO;
    }

    const uint8_t *payload = page + HEADER_SIZE;
    uint32_t c = page_crc32_bound(h.lba, h.seq, h.data_len, payload);
    if (c != h.crc32)
    {
        free(page);
        return -EIO;
    }

    *out_crc32 = h.crc32;
    free(page);
    return 0;
}

int ftl_validate_page_for_lba(const ftl_t *f, uint32_t pba, uint32_t expect_lba, uint64_t expect_seq, uint32_t expect_crc32)
{
    if (!f)
        return -EINVAL;
    if (pba >= NUM_PAGES)
        return -ERANGE;

    uint8_t *page = (uint8_t *)malloc(PAGE_SIZE);
    if (!page)
        return -ENOMEM;

    int rc = flash_read_page(&f->flash, pba, page, PAGE_SIZE);
    if (rc != 0)
    {
        free(page);
        return rc;
    }

    page_hdr_t h;
    pagehdr_decode(&h, page);

    int ok = 1;
    if (h.magic != FLASH_MAGIC_PAGE ||
        (h.flags & PAGE_FLAG_VALID) == 0 ||
        h.version != FLASH_PAGE_VERSION ||
        h.lba != expect_lba ||
        h.seq != expect_seq ||
        h.data_len != LBA_SIZE)
    {
        ok = 0;
    }
    else
    {
        const uint8_t *payload = page + HEADER_SIZE;

        uint32_t c = page_crc32_bound(h.lba, h.seq, h.data_len, payload);
        if (c != h.crc32)
            ok = 0;
        else if (h.crc32 != expect_crc32)
            ok = 0;
    }

    free(page);
    return ok ? 0 : -EIO;
}
