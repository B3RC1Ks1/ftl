/*
 * Implementacja bazy snapshotów (snapdb) i operacji snapshot_create/snapshot_restore dla FTL.
 * Snapshot jest zapisywany jako binarny blob zawierający ID oraz mapowanie LBA->(PBA, seq, crc32 strony),
 * a następnie podpisywany Ed25519 (OpenSSL EVP). Przy wczytywaniu bazy rekordy są weryfikowane podpisem, a ID kanonizowane
 * na podstawie danych w blobie. Odtwarzanie snapshotu waliduje zgodność stron na flashu (nagłówek + CRC) i nie przyjmuje
 * cichych uszkodzeń: brakujące/niepoprawne strony pozostają jako INVALID_PBA w odtworzonym mapowaniu.
 */

#include "snapshot.h"
#include "ftl_config.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* Snapshot blob:
 * u32 magic (SNPB), u32 version (=2),
 * u32 id_len, bytes id,
 * u32 num_lbas,
 * repeated entries:
 *   u32 lba, u32 pba, u64 seq, u32 page_crc32
 */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
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
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
static uint64_t get_u64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i] << (8 * i));
    return v;
}

static int blob_get_id(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t **out_id, uint32_t *out_id_len)
{
    if (!blob || blob_len < 12 || !out_id || !out_id_len)
        return -EINVAL;

    const uint8_t *p = blob;

    uint32_t magic = get_u32le(p);
    p += 4;
    uint32_t ver = get_u32le(p);
    p += 4;
    uint32_t id_len = get_u32le(p);
    p += 4;

    if (magic != SNAP_BLOB_MAGIC || ver != 2u)
        return -EINVAL;
    if (id_len == 0 || id_len > 1024u)
        return -EINVAL;
    if (12u + id_len > blob_len)
        return -EINVAL;

    *out_id = p;
    *out_id_len = id_len;
    return 0;
}

typedef struct snaprec
{
    char *id;
    uint8_t *blob;
    uint32_t blob_len;
    uint8_t sig[SNAP_SIG_LEN];
    struct snaprec *next;
} snaprec_t;

struct snapdb
{
    FILE *fp;
    char *path;
    snaprec_t *head;
};

static void free_rec(snaprec_t *r)
{
    if (!r)
        return;
    free(r->id);
    free(r->blob);
    free(r);
}

static snaprec_t *find_rec(const snapdb_t *db, const char *id)
{
    for (snaprec_t *r = db->head; r; r = r->next)
    {
        if (strcmp(r->id, id) == 0)
            return r;
    }
    return NULL;
}

static int load_db(snapdb_t *db)
{
    if (fseek(db->fp, 0, SEEK_SET) != 0)
        return -errno;

    for (;;)
    {
        uint8_t hdr[24];
        size_t rd = fread(hdr, 1, sizeof(hdr), db->fp);

        if (rd == 0)
            break;
        if (rd != sizeof(hdr))
            break;

        uint32_t magic = get_u32le(hdr + 0);
        uint32_t ver = get_u32le(hdr + 4);
        uint32_t id_len = get_u32le(hdr + 8);
        uint32_t blob_len = get_u32le(hdr + 12);
        uint32_t sig_len = get_u32le(hdr + 16);
        (void)get_u32le(hdr + 20); /* reserved */

        if (magic != SNAP_DB_MAGIC || ver != 1u)
            return -EINVAL;
        if (id_len == 0 || id_len > 1024u)
            return -EINVAL;
        if (blob_len == 0 || blob_len > (16u * 1024u * 1024u))
            return -EINVAL;
        if (sig_len != SNAP_SIG_LEN)
            return -EINVAL;

        char *outer_id = (char *)malloc((size_t)id_len + 1);
        uint8_t *blob = (uint8_t *)malloc(blob_len);
        uint8_t sig[SNAP_SIG_LEN];

        if (!outer_id || !blob)
        {
            free(outer_id);
            free(blob);
            return -ENOMEM;
        }

        if (fread(outer_id, 1, id_len, db->fp) != id_len)
        {
            free(outer_id);
            free(blob);
            break;
        }
        outer_id[id_len] = 0;

        if (fread(blob, 1, blob_len, db->fp) != blob_len)
        {
            free(outer_id);
            free(blob);
            break;
        }
        if (fread(sig, 1, SNAP_SIG_LEN, db->fp) != SNAP_SIG_LEN)
        {
            free(outer_id);
            free(blob);
            break;
        }

        if (crypto_verify_ed25519(sig, blob, blob_len) != 0)
        {
            free(outer_id);
            free(blob);
            continue;
        }

        const uint8_t *blob_id = NULL;
        uint32_t blob_id_len = 0;
        if (blob_get_id(blob, blob_len, &blob_id, &blob_id_len) != 0)
        {
            free(outer_id);
            free(blob);
            return -EINVAL;
        }

        char *canon_id = (char *)malloc((size_t)blob_id_len + 1);
        if (!canon_id)
        {
            free(outer_id);
            free(blob);
            return -ENOMEM;
        }
        memcpy(canon_id, blob_id, blob_id_len);
        canon_id[blob_id_len] = 0;

        (void)outer_id;
        free(outer_id);

        snaprec_t *r = (snaprec_t *)calloc(1, sizeof(*r));
        if (!r)
        {
            free(canon_id);
            free(blob);
            return -ENOMEM;
        }
        r->id = canon_id;
        r->blob = blob;
        r->blob_len = blob_len;
        memcpy(r->sig, sig, SNAP_SIG_LEN);

        r->next = db->head;
        db->head = r;
    }

    return 0;
}

int snapdb_open(snapdb_t **out, const char *path, int create_fresh)
{
    if (!out || !path)
        return -EINVAL;
    *out = NULL;

    if (crypto_init() != 0)
        return -EINVAL;

    snapdb_t *db = (snapdb_t *)calloc(1, sizeof(*db));
    if (!db)
        return -ENOMEM;

    db->path = strdup(path);
    if (!db->path)
    {
        free(db);
        return -ENOMEM;
    }

    db->fp = fopen(path, create_fresh ? "wb+" : "rb+");
    if (!db->fp && !create_fresh)
    {
        db->fp = fopen(path, "wb+");
    }
    if (!db->fp)
    {
        free(db->path);
        free(db);
        return -errno;
    }

    if (!create_fresh)
    {
        int rc = load_db(db);
        if (rc != 0)
        {
            fclose(db->fp);
            free(db->path);
            free(db);
            return rc;
        }
    }

    *out = db;
    return 0;
}

int snapdb_close(snapdb_t *db)
{
    if (!db)
        return -EINVAL;

    snaprec_t *r = db->head;
    while (r)
    {
        snaprec_t *n = r->next;
        free_rec(r);
        r = n;
    }

    if (db->fp)
        fclose(db->fp);

    free(db->path);
    free(db);
    crypto_cleanup();
    return 0;
}

void snapshot_list(const snapdb_t *db)
{
    printf("Snapshots:\n");
    for (snaprec_t *r = db->head; r; r = r->next)
    {
        printf(" - %s (blob=%u bytes)\n", r->id, r->blob_len);
    }
}

int snapshot_create(snapdb_t *db, ftl_t *ftl, const char *id)
{
    if (!db || !ftl || !id)
        return -EINVAL;
    if (strlen(id) == 0 || strlen(id) > 256)
        return -EINVAL;

    if (find_rec(db, id) != NULL)
        return -EEXIST;

    uint32_t n = ftl_num_lbas(ftl);
    uint32_t id_len = (uint32_t)strlen(id);

    uint32_t blob_len = 4 + 4 + 4 + id_len + 4 + n * (4 + 4 + 8 + 4);
    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (!blob)
        return -ENOMEM;

    uint8_t *p = blob;
    put_u32le(p, SNAP_BLOB_MAGIC);
    p += 4;
    put_u32le(p, 2u);
    p += 4;
    put_u32le(p, id_len);
    p += 4;
    memcpy(p, id, id_len);
    p += id_len;
    put_u32le(p, n);
    p += 4;

    for (uint32_t l = 0; l < n; l++)
    {
        uint32_t pba;
        uint64_t seq;
        ftl_get_mapping(ftl, l, &pba, &seq);

        uint32_t page_crc = 0;

        if (pba != INVALID_PBA)
        {
            if (ftl_get_page_crc_for_lba(ftl, pba, l, seq, &page_crc) != 0)
            {
                pba = INVALID_PBA;
                seq = 0;
                page_crc = 0;
            }
        }

        put_u32le(p, l);
        p += 4;
        put_u32le(p, pba);
        p += 4;
        put_u64le(p, seq);
        p += 8;
        put_u32le(p, page_crc);
        p += 4;
    }

    uint8_t sig[SNAP_SIG_LEN];
    if (crypto_sign_ed25519(sig, blob, blob_len) != 0)
    {
        free(blob);
        return -EINVAL;
    }

    fseek(db->fp, 0, SEEK_END);

    uint8_t hdr[24];
    put_u32le(hdr + 0, SNAP_DB_MAGIC);
    put_u32le(hdr + 4, 1u);
    put_u32le(hdr + 8, id_len);
    put_u32le(hdr + 12, blob_len);
    put_u32le(hdr + 16, SNAP_SIG_LEN);
    put_u32le(hdr + 20, 0u);

    if (fwrite(hdr, 1, sizeof(hdr), db->fp) != sizeof(hdr) ||
        fwrite(id, 1, id_len, db->fp) != id_len ||
        fwrite(blob, 1, blob_len, db->fp) != blob_len ||
        fwrite(sig, 1, SNAP_SIG_LEN, db->fp) != SNAP_SIG_LEN)
    {
        free(blob);
        return -EIO;
    }

    if (fflush(db->fp) != 0)
    {
        int e = -errno;
        free(blob);
        return (e != 0) ? e : -EIO;
    }
    int fd = fileno(db->fp);
    if (fd < 0)
    {
        free(blob);
        return -errno;
    }
    if (fsync(fd) != 0)
    {
        int e = -errno;
        free(blob);
        return (e != 0) ? e : -EIO;
    }

    snaprec_t *r = (snaprec_t *)calloc(1, sizeof(*r));
    if (!r)
    {
        free(blob);
        return -ENOMEM;
    }
    r->id = strdup(id);
    if (!r->id)
    {
        free(r);
        free(blob);
        return -ENOMEM;
    }
    r->blob = blob;
    r->blob_len = blob_len;
    memcpy(r->sig, sig, SNAP_SIG_LEN);
    r->next = db->head;
    db->head = r;

    return 0;
}

int snapshot_restore(snapdb_t *db, ftl_t *ftl, const char *id)
{
    if (!db || !ftl || !id)
        return -EINVAL;

    snaprec_t *r = find_rec(db, id);
    if (!r)
        return -ENOENT;

    if (crypto_verify_ed25519(r->sig, r->blob, r->blob_len) != 0)
        return -EACCES;

    const uint8_t *p = r->blob;
    if (r->blob_len < 16)
        return -EINVAL;

    uint32_t magic = get_u32le(p);
    p += 4;
    uint32_t ver = get_u32le(p);
    p += 4;
    uint32_t id_len = get_u32le(p);
    p += 4;

    if (magic != SNAP_BLOB_MAGIC || ver != 2u)
        return -EINVAL;
    if (id_len == 0 || id_len > 1024u)
        return -EINVAL;
    if ((size_t)(p - r->blob + id_len + 4) > r->blob_len)
        return -EINVAL;

    const uint8_t *blob_id = p;
    p += id_len;

    size_t want_len = strlen(id);
    if (want_len != (size_t)id_len || memcmp(blob_id, id, id_len) != 0)
        return -EINVAL;

    uint32_t n = get_u32le(p);
    p += 4;
    if (n != ftl_num_lbas(ftl))
        return -EINVAL;

    uint32_t *new_pba = (uint32_t *)malloc(sizeof(uint32_t) * n);
    uint64_t *new_seq = (uint64_t *)malloc(sizeof(uint64_t) * n);
    if (!new_pba || !new_seq)
    {
        free(new_pba);
        free(new_seq);
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < n; i++)
    {
        new_pba[i] = INVALID_PBA;
        new_seq[i] = 0;
    }

    for (uint32_t i = 0; i < n; i++)
    {
        if ((size_t)(p - r->blob + (4 + 4 + 8 + 4)) > r->blob_len)
        {
            free(new_pba);
            free(new_seq);
            return -EINVAL;
        }

        uint32_t lba = get_u32le(p);
        p += 4;
        uint32_t pba = get_u32le(p);
        p += 4;
        uint64_t seq = get_u64le(p);
        p += 8;
        uint32_t expect_crc = get_u32le(p);
        p += 4;

        if (lba >= n)
            continue;
        if (pba == INVALID_PBA)
            continue;

        int vrc = ftl_validate_page_for_lba(ftl, pba, lba, seq, expect_crc);
        if (vrc == 0)
        {
            new_pba[lba] = pba;
            new_seq[lba] = seq;
        }
        else
        {
            /* missing: no silent corruption */
        }
    }

    int rc = ftl_apply_mapping(ftl, new_pba, new_seq);
    free(new_pba);
    free(new_seq);
    return rc;
}
