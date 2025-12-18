# GOODRAM FTL DEMO - HUBERT SERAFIN

## Model

- Flash to jeden plik `flash.bin`, podzielony na `NUM_PAGES` stron po `PAGE_SIZE` bajtów.
- Każda strona składa się z nagłówka (64 B) oraz payloadu.
- Jedno LBA mapuje się na jedną stronę fizyczną.
- W tym demo zawsze zapisujemy dokładnie `LBA_SIZE` bajtów danych:
  - `data_len` w nagłówku strony musi być równe `LBA_SIZE`,
  - pozostała część strony (`PAGE_SIZE - HEADER_SIZE - LBA_SIZE`) jest niewykorzystana.

## Log-structured write

- `ftl_write()` zawsze alokuje nową stronę fizyczną (PBA) i zapisuje tam dane.
- Poprzednia strona dla danego LBA staje się stale (nie jest już częścią bieżącego mapowania).
- Gdy brakuje wolnych stron, uruchamiane jest proste GC:
  - skan liniowy od `gc_cursor`,
  - wybierana jest pierwsza strona spełniająca warunek `used=1 && live=0`,
  - strona jest kasowana (zerowana) i wraca do puli wolnych stron.

## Metadane stron i brak silent data corruption

Każda strona ma w nagłówku:
- `magic`, `version`, `flags`,
- `lba` - logiczny adres bloku,
- `seq` - globalny, monotoniczny licznik zapisów,
- `data_len`,
- `crc32`.

Kluczowe: `crc32` nie jest liczone wyłącznie z payloadu. Jest liczone jako CRC32 z:

`lba (LE) || seq (LE) || data_len (LE) || payload[data_len]`

Dzięki temu:
- jeśli nagłówek strony ulegnie uszkodzeniu (np. bit-flip zmieni `lba` lub `seq`), CRC przestanie pasować,
- strona nie zostanie błędnie zaakceptowana jako dane innego LBA,
- przy `ftl_read()` i `snapshot_restore()` nigdy nie zwracamy danych z innego LBA (brak silent data corruption).

Strona jest uznana za poprawną tylko jeśli:
- `magic`, `version` i `flags` są poprawne,
- `lba` w nagłówku == oczekiwany `lba`,
- `seq` == oczekiwany `seq`,
- `data_len == LBA_SIZE`,
- CRC bound pasuje.

Jeśli którykolwiek warunek nie jest spełniony:
- dane dla danego LBA są traktowane jako missing,
- do bufora użytkownika wpisywane są zera,
- funkcja zwraca `-EIO`, jeśli choć jedno LBA było missing.

## Snapshoty

- Snapshot to zapis mapowania: `LBA -> (PBA, seq, page_crc32)`.
- Snapshoty są zapisywane do osobnego pliku `snap.db`.
- Każdy snapshot jest podpisany Ed25519 (OpenSSL).
- Przy wczytywaniu bazy snapshotów rekordy z niepoprawnym podpisem są ignorowane.
- Podczas restore:
  - weryfikowany jest podpis,
  - sprawdzane jest, że `id` snapshotu zgadza się z `id` zapisanym wewnątrz podpisanego bloba (nagłówek rekordu w `snap.db` nie jest źródłem prawdy),
  - dla każdego LBA walidowana jest strona na flashu (nagłówek + bound CRC + exact match `page_crc32`).

Duplikaty `id` są blokowane: `snap_create` zwraca błąd, jeśli snapshot o danym `id` już istnieje.

### Wersjonowanie bloba

- Snapshot blob ma wersję 2.
- Wersja 2 dodaje pole `page_crc32` per LBA.
- Dzięki temu snapshot jest powiązany z konkretną instancją strony: nawet jeśli pojawi się strona z pasującym `(lba, seq)`, ale inną treścią, restore ją odrzuci.

## Durability snapshotów

- Po dopisaniu snapshotu do `snap.db` wykonywane jest `fflush()` oraz `fsync()` na deskryptorze pliku.
- Zmniejsza to ryzyko utraty snapshotu po awarii zasilania lub systemu (best effort, bez gwarancji atomowości).

## Best effort - ograniczenia

- Snapshot może utracić część danych, jeśli strony referencjonowane przez snapshot zostały później skasowane przez GC i ponownie użyte.
- W takiej sytuacji restore nie odtwarza danego LBA (pozostaje unmapped/missing), ale nigdy nie zwraca danych z innego LBA.

## Zachowanie przy braku wolnych stron

- Jeśli flash jest pełny i nie ma żadnych stron stale do odzyskania, `ftl_write()` zwraca `-ENOSPC`.

## Security considerations

- Klucz Ed25519 jest w tym demo deterministycznie generowany z hardcoded seeda.
- Jest to wyłącznie rozwiązanie demonstracyjne.
- W realnym systemie klucz prywatny musi być przechowywany poza kodem (inaczej podpis nie zapewnia autentyczności).
- Stare pliki `snap.db` (z blobami wersji 1) nie są kompatybilne z bieżącą wersją kodu.

## Kompilacja

Program został przetestowany na WSL.
Wymaga OpenSSL (`libcrypto`).

```bash
make
```

## Przykładowy scenariusz demo
1) Fresh init:
- `./ftl_demo flash.bin snap.db fresh`

2) Zapis LBA 0..3 tag=1:
- `./ftl_demo flash.bin snap.db write 0 4 1`

3) Snapshot:
- `./ftl_demo flash.bin snap.db snap_create s1`

4) Nadpisz te same LBA tag=2:
- `./ftl_demo flash.bin snap.db write 0 4 2`

5) Wymuś GC i reuse:
- `./ftl_demo flash.bin snap.db stress 1000`

6) Restore snapshot:
- `./ftl_demo flash.bin snap.db snap_restore s1`

7) Odczyt 0..3:
- `./ftl_demo flash.bin snap.db read 0 4`