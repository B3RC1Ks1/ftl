#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct flash
{
    int fd;
    uint32_t page_size;
    uint32_t num_pages;
} flash_t;

int flash_open(flash_t *f, const char *path, uint32_t page_size, uint32_t num_pages, int create_fresh);
int flash_close(flash_t *f);

int flash_read_page(const flash_t *f, uint32_t pba, void *buf, size_t len);
int flash_write_page(const flash_t *f, uint32_t pba, const void *buf, size_t len);
int flash_erase_page(const flash_t *f, uint32_t pba);

int flash_fsync(const flash_t *f);
