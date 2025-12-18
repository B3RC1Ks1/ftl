#pragma once
#include "flash.h"
#include <stdint.h>
#include <stddef.h>

typedef struct ftl ftl_t;

int ftl_open(ftl_t **out, const char *flash_path, int create_fresh);
int ftl_close(ftl_t *f);

int ftl_write(ftl_t *f, uint32_t lba, const void *buf, uint32_t nblocks);
int ftl_read(ftl_t *f, uint32_t lba, void *buf, uint32_t nblocks);

/* Debug/demo */
void ftl_dump_map(const ftl_t *f);

/* Snapshot integration helpers (used by snapshot.c) */
uint32_t ftl_num_lbas(const ftl_t *f);
int ftl_get_mapping(const ftl_t *f, uint32_t lba, uint32_t *pba, uint64_t *seq);
int ftl_apply_mapping(ftl_t *f, const uint32_t *pba, const uint64_t *seq);

/* Snapshot stores expected page crc32 (from page header) */
int ftl_get_page_crc_for_lba(const ftl_t *f, uint32_t pba, uint32_t expect_lba, uint64_t expect_seq, uint32_t *out_crc32);

/* Validate page AND ensure it matches snapshot’s expected crc32 */
int ftl_validate_page_for_lba(const ftl_t *f, uint32_t pba, uint32_t expect_lba, uint64_t expect_seq, uint32_t expect_crc32);
