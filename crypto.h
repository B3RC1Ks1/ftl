#pragma once
#include <stddef.h>
#include <stdint.h>

#define SNAP_SIG_LEN 64
#define SNAP_PUBKEY_LEN 32

int crypto_init(void);
void crypto_cleanup(void);

int crypto_sign_ed25519(uint8_t sig[SNAP_SIG_LEN], const uint8_t *msg, size_t msglen);
int crypto_verify_ed25519(const uint8_t sig[SNAP_SIG_LEN], const uint8_t *msg, size_t msglen);
