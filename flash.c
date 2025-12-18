/*
 * Prosta emulacja pamięci flash na pliku.
 * Kod udostępnia operacje: otwarcie/utworzenie pliku o zadanym rozmiarze (stronicowanie),
 * odczyt i zapis strony (PBA), kasowanie strony przez wyzerowanie oraz fsync.
 */

#include "flash.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

static off_t page_off(const flash_t *f, uint32_t pba)
{
    return (off_t)pba * (off_t)f->page_size;
}

int flash_open(flash_t *f, const char *path, uint32_t page_size, uint32_t num_pages, int create_fresh)
{
    if (!f || !path)
        return -EINVAL;
    memset(f, 0, sizeof(*f));
    f->page_size = page_size;
    f->num_pages = num_pages;

    int flags = O_RDWR | O_CREAT;
    f->fd = open(path, flags, 0644);
    if (f->fd < 0)
        return -errno;

    off_t want = (off_t)page_size * (off_t)num_pages;

    if (create_fresh)
    {
        if (ftruncate(f->fd, 0) != 0)
        {
            int e = -errno;
            close(f->fd);
            return e;
        }
        if (ftruncate(f->fd, want) != 0)
        {
            int e = -errno;
            close(f->fd);
            return e;
        }

        void *z = calloc(1, page_size);
        if (!z)
        {
            close(f->fd);
            return -ENOMEM;
        }
        for (uint32_t i = 0; i < num_pages; i++)
        {
            ssize_t w = pwrite(f->fd, z, page_size, page_off(f, i));
            if (w != (ssize_t)page_size)
            {
                int e = (w < 0) ? -errno : -EIO;
                free(z);
                close(f->fd);
                return e;
            }
        }
        free(z);
        if (fsync(f->fd) != 0)
        {
            int e = -errno;
            close(f->fd);
            return e;
        }
    }
    else
    {
        struct stat st;
        if (fstat(f->fd, &st) != 0)
        {
            int e = -errno;
            close(f->fd);
            return e;
        }
        if (st.st_size < want)
        {
            if (ftruncate(f->fd, want) != 0)
            {
                int e = -errno;
                close(f->fd);
                return e;
            }
        }
    }

    return 0;
}

int flash_close(flash_t *f)
{
    if (!f)
        return -EINVAL;
    if (f->fd >= 0)
        close(f->fd);
    f->fd = -1;
    return 0;
}

int flash_read_page(const flash_t *f, uint32_t pba, void *buf, size_t len)
{
    if (!f || !buf)
        return -EINVAL;
    if (pba >= f->num_pages)
        return -ERANGE;
    if (len > f->page_size)
        return -EINVAL;

    ssize_t r = pread(f->fd, buf, len, page_off(f, pba));
    if (r != (ssize_t)len)
        return (r < 0) ? -errno : -EIO;
    return 0;
}

int flash_write_page(const flash_t *f, uint32_t pba, const void *buf, size_t len)
{
    if (!f || !buf)
        return -EINVAL;
    if (pba >= f->num_pages)
        return -ERANGE;
    if (len > f->page_size)
        return -EINVAL;

    ssize_t w = pwrite(f->fd, buf, len, page_off(f, pba));
    if (w != (ssize_t)len)
        return (w < 0) ? -errno : -EIO;
    return 0;
}

int flash_erase_page(const flash_t *f, uint32_t pba)
{
    if (!f)
        return -EINVAL;
    if (pba >= f->num_pages)
        return -ERANGE;

    void *z = calloc(1, f->page_size);
    if (!z)
        return -ENOMEM;
    int rc = flash_write_page(f, pba, z, f->page_size);
    free(z);
    return rc;
}

int flash_fsync(const flash_t *f)
{
    if (!f)
        return -EINVAL;
    return (fsync(f->fd) == 0) ? 0 : -errno;
}
