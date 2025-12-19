/*
 * Prosty program CLI do testowania emulowanej pamięci flash, warstwy FTL oraz bazy snapshotów.
 * Umożliwia: inicjalizację "fresh", zapis/odczyt bloków LBA, tworzenie i odtwarzanie snapshotów,
 * listowanie snapshotów, podgląd mapowania LBA->PBA oraz test obciążeniowy wymuszający reuse stron (GC).
 */

#include "ftl.h"
#include "snapshot.h"
#include "ftl_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void hexdump16(const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    size_t n = (len > 16) ? 16 : len;
    for (size_t i = 0; i < n; i++)
        printf("%02x ", p[i]);
}

static void usage(const char *argv0)
{
    printf("Usage:\n");
    printf("  %s <flash.bin> <snap.db> fresh\n", argv0);
    printf("  %s <flash.bin> <snap.db> write  <lba> <nblocks> <tag_u32>\n", argv0);
    printf("  %s <flash.bin> <snap.db> read   <lba> <nblocks>\n", argv0);
    printf("  %s <flash.bin> <snap.db> snap_create  <id>\n", argv0);
    printf("  %s <flash.bin> <snap.db> snap_restore <id>\n", argv0);
    printf("  %s <flash.bin> <snap.db> snap_restore_read <id> <lba> <nblocks>\n", argv0);
    printf("  %s <flash.bin> <snap.db> snap_list\n", argv0);
    printf("  %s <flash.bin> <snap.db> map\n", argv0);
    printf("  %s <flash.bin> <snap.db> stress <iters>   (wymusza reuse stron)\n", argv0);
}

static void fill_block(unsigned char *blk, uint32_t lba, uint32_t tag)
{
    /* prosta sygnatura danych */
    memset(blk, 0, LBA_SIZE);
    blk[0] = (unsigned char)(lba);
    blk[1] = (unsigned char)(lba >> 8);
    blk[2] = (unsigned char)(tag);
    blk[3] = (unsigned char)(tag >> 8);
    for (size_t i = 4; i < LBA_SIZE; i++)
    {
        blk[i] = (unsigned char)((lba * 131u + tag * 17u + (uint32_t)i) & 0xFFu);
    }
}

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        usage(argv[0]);
        return 2;
    }

    const char *flash_path = argv[1];
    const char *snap_path = argv[2];
    const char *cmd = argv[3];

    int create_fresh = (strcmp(cmd, "fresh") == 0);

    ftl_t *ftl = NULL;
    snapdb_t *db = NULL;

    int rc = ftl_open(&ftl, flash_path, create_fresh);
    if (rc != 0)
    {
        fprintf(stderr, "ftl_open: %s\n", strerror(-rc));
        return 1;
    }

    rc = snapdb_open(&db, snap_path, create_fresh);
    if (rc != 0)
    {
        fprintf(stderr, "snapdb_open: %s\n", strerror(-rc));
        ftl_close(ftl);
        return 1;
    }

    if (strcmp(cmd, "fresh") == 0)
    {
        printf("Fresh init done. NUM_PAGES=%u NUM_LBAS=%u PAGE_SIZE=%u LBA_SIZE=%u\n",
               NUM_PAGES, NUM_LBAS, PAGE_SIZE, LBA_SIZE);
    }
    else if (strcmp(cmd, "write") == 0)
    {
        if (argc != 7)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
        uint32_t lba = (uint32_t)strtoul(argv[4], NULL, 0);
        uint32_t n = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t tag = (uint32_t)strtoul(argv[6], NULL, 0);

        unsigned char *buf = (unsigned char *)malloc((size_t)n * LBA_SIZE);
        if (!buf)
        {
            rc = -ENOMEM;
            goto out;
        }
        for (uint32_t i = 0; i < n; i++)
            fill_block(buf + (size_t)i * LBA_SIZE, lba + i, tag);

        rc = ftl_write(ftl, lba, buf, n);
        free(buf);
        if (rc != 0)
            fprintf(stderr, "write: %s\n", strerror(-rc));
        else
            printf("write OK\n");
    }
    else if (strcmp(cmd, "read") == 0)
    {
        if (argc != 6)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
        uint32_t lba = (uint32_t)strtoul(argv[4], NULL, 0);
        uint32_t n = (uint32_t)strtoul(argv[5], NULL, 0);

        unsigned char *buf = (unsigned char *)malloc((size_t)n * LBA_SIZE);
        if (!buf)
        {
            rc = -ENOMEM;
            goto out;
        }

        rc = ftl_read(ftl, lba, buf, n);
        for (uint32_t i = 0; i < n; i++)
        {
            unsigned char *blk = buf + (size_t)i * LBA_SIZE;
            printf("LBA %u: ", lba + i);
            hexdump16(blk, LBA_SIZE);
            printf("\n");
        }
        if (rc != 0)
            fprintf(stderr, "read: partial/missing data (%s)\n", strerror(-rc));
        free(buf);
    }
    else if (strcmp(cmd, "snap_create") == 0)
    {
        if (argc != 5)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
        rc = snapshot_create(db, ftl, argv[4]);
        if (rc != 0)
        {
            if (rc == -EEXIST)
                fprintf(stderr, "snap_create: snapshot id '%s' already exists\n", argv[4]);
            else
                fprintf(stderr, "snap_create: %s\n", strerror(-rc));
        }
        else
        {
            printf("snap_create OK\n");
        }
    }
    else if (strcmp(cmd, "snap_restore") == 0)
    {
        if (argc != 5)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
        rc = snapshot_restore(db, ftl, argv[4]);
        if (rc != 0)
            fprintf(stderr, "snap_restore: %s\n", strerror(-rc));
        else
            printf("snap_restore OK\n");
    }
    else if (strcmp(cmd, "snap_restore_read") == 0)
    {
        if (argc != 7)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }

        const char *sid = argv[4];
        uint32_t lba = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t n = (uint32_t)strtoul(argv[6], NULL, 0);

        rc = snapshot_restore(db, ftl, sid);
        if (rc != 0)
        {
            fprintf(stderr, "snap_restore: %s\n", strerror(-rc));
            goto out;
        }
        printf("snap_restore OK\n");

        unsigned char *buf = (unsigned char *)malloc((size_t)n * LBA_SIZE);
        if (!buf)
        {
            rc = -ENOMEM;
            goto out;
        }

        rc = ftl_read(ftl, lba, buf, n);
        for (uint32_t i = 0; i < n; i++)
        {
            unsigned char *blk = buf + (size_t)i * LBA_SIZE;
            printf("LBA %u: ", lba + i);
            hexdump16(blk, LBA_SIZE);
            printf("\n");
        }
        if (rc != 0)
            fprintf(stderr, "read: partial/missing data (%s)\n", strerror(-rc));

        free(buf);
    }
    else if (strcmp(cmd, "snap_list") == 0)
    {
        snapshot_list(db);
    }
    else if (strcmp(cmd, "map") == 0)
    {
        ftl_dump_map(ftl);
    }
    else if (strcmp(cmd, "stress") == 0)
    {
        if (argc != 5)
        {
            usage(argv[0]);
            rc = -EINVAL;
            goto out;
        }
        uint32_t iters = (uint32_t)strtoul(argv[4], NULL, 0);

        unsigned char *blk = (unsigned char *)malloc(LBA_SIZE);
        if (!blk)
        {
            rc = -ENOMEM;
            goto out;
        }

        /* zapis rotacyjny po LBA, żeby szybko zapełnić flash i wymusić GC/reuse stale stron */
        for (uint32_t k = 0; k < iters; k++)
        {
            uint32_t lba = k % NUM_LBAS;
            uint32_t tag = 0xA0000000u ^ k;
            fill_block(blk, lba, tag);
            rc = ftl_write(ftl, lba, blk, 1);
            if (rc != 0)
            {
                fprintf(stderr, "stress write failed at iter=%u: %s\n", k, strerror(-rc));
                break;
            }
        }
        free(blk);
        if (rc == 0)
            printf("stress OK\n");
    }
    else
    {
        usage(argv[0]);
        rc = -EINVAL;
    }

out:
    snapdb_close(db);
    ftl_close(ftl);
    return (rc == 0) ? 0 : 1;
}
