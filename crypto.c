/*
 * Implementacja prostego modułu kryptograficznego opartego na Ed25519 (OpenSSL EVP).
 * Kod inicjalizuje deterministyczną parę kluczy z ustalonego seeda (do celów demo),
 * udostępnia funkcje do podpisywania i weryfikacji wiadomości oraz obsługuje
 * poprawne zwalnianie zasobów kryptograficznych.
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <string.h>

static EVP_PKEY *g_priv = NULL;
static EVP_PKEY *g_pub = NULL;

/* Demo seed, stały, deterministyczny. W prawdziwej aplikacji trzymamy prywatny klucz poza kodem. */
static const uint8_t DEMO_SEED[32] = {
    0x42, 0x11, 0x7a, 0x9c, 0x20, 0x5e, 0x1d, 0xa7, 0x9b, 0x33, 0x0f, 0xc1, 0x8d, 0x04, 0xaa, 0x77,
    0x63, 0x2e, 0x99, 0x10, 0x4d, 0x55, 0x6a, 0x3c, 0x88, 0xef, 0x01, 0x2b, 0x7d, 0x6c, 0x90, 0x5a};

int crypto_init(void)
{
    if (g_priv || g_pub)
        return 0;

    g_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, DEMO_SEED, sizeof(DEMO_SEED));
    if (!g_priv)
        return -1;

    uint8_t pub[SNAP_PUBKEY_LEN];
    size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(g_priv, pub, &publen) != 1 || publen != SNAP_PUBKEY_LEN)
    {
        EVP_PKEY_free(g_priv);
        g_priv = NULL;
        return -1;
    }

    g_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, publen);
    if (!g_pub)
    {
        EVP_PKEY_free(g_priv);
        g_priv = NULL;
        return -1;
    }
    return 0;
}

void crypto_cleanup(void)
{
    if (g_pub)
        EVP_PKEY_free(g_pub);
    if (g_priv)
        EVP_PKEY_free(g_priv);
    g_pub = NULL;
    g_priv = NULL;
}

int crypto_sign_ed25519(uint8_t sig[SNAP_SIG_LEN], const uint8_t *msg, size_t msglen)
{
    if (!g_priv || !sig || (!msg && msglen))
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    size_t siglen = SNAP_SIG_LEN;
    int ok = (EVP_DigestSignInit(ctx, NULL, NULL, NULL, g_priv) == 1) &&
             (EVP_DigestSign(ctx, sig, &siglen, msg, msglen) == 1) &&
             (siglen == SNAP_SIG_LEN);

    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int crypto_verify_ed25519(const uint8_t sig[SNAP_SIG_LEN], const uint8_t *msg, size_t msglen)
{
    if (!g_pub || !sig || (!msg && msglen))
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    int ok = (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, g_pub) == 1) &&
             (EVP_DigestVerify(ctx, sig, SNAP_SIG_LEN, msg, msglen) == 1);

    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}
