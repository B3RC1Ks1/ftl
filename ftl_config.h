/*
 * Konfiguracja demo dla emulowanej pamięci flash i warstwy FTL.
 * Definiuje stałe formatu stron (magia, wersja, rozmiary), parametry geometrii (liczba stron i LBA),
 * rozmiar bloku logicznego oraz wartości specjalne używane w mapowaniu (np. INVALID_PBA).
 */

#pragma once
#include <stdint.h>

/*
 * Demo konfiguracja
 */

#define FLASH_MAGIC_PAGE 0x50414745u /* "PAGE" */
#define FLASH_PAGE_VERSION 1u

#define SNAP_DB_MAGIC 0x534E5031u   /* "SNP1" */
#define SNAP_BLOB_MAGIC 0x534E5042u /* "SNPB" */

#define PAGE_SIZE 4096u
#define HEADER_SIZE 64u

#define NUM_PAGES 128u
#define NUM_LBAS 64u

#define LBA_SIZE 512u /* nblocks liczone w jednostkach LBA_SIZE */

#if (LBA_SIZE > (PAGE_SIZE - HEADER_SIZE))
#error "LBA_SIZE must be <= PAGE_SIZE - HEADER_SIZE"
#endif

#define INVALID_PBA 0xFFFFFFFFu
