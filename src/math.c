// custom math routines for shallot

#include "math.h"
#include "defines.h"
#include <openssl/opensslv.h>

void int_pow(uint32_t base, uint8_t pwr, uint64_t *out) { // integer pow()
  *out = (uint64_t)base;
  uint8_t round = 1;
  for(; round < pwr; round++)
    *out *= base;
}

// LCM for BIGNUMs
uint8_t BN_lcm(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *gcd, BN_CTX *ctx) {
  BIGNUM *tmp = BN_CTX_get(ctx);
  if(!BN_div(tmp, NULL, a, gcd, ctx))
    return 0;
  if(!BN_mul(r, b, tmp, ctx))
    return 0;
  return 1;
}

// wraps RSA key generation, DER encoding, and initial SHA-1 hashing
RSA *easygen(uint16_t num, uint8_t len, uint8_t *der, uint8_t edl,
             SHA_CTX *ctx) {
  uint8_t der_len;
  RSA *rsa;

  for(;;) { // ugly, I know, but better than using goto IMHO
    rsa = RSA_generate_key(num, 3, NULL, NULL);

    if(!rsa) // if key generation fails (no [P]RNG seed?)
      return rsa;

    // encode RSA key in X.690 DER format
    uint8_t *tmp = der;
    der_len = i2d_RSAPublicKey(rsa, &tmp);

    if(der_len == edl - len + 1)
      break; // encoded key was the correct size, keep going

    RSA_free(rsa); // encoded key was the wrong size, try again
  }

  // adjust for the actual size of e
  der[RSA_ADD_DER_OFF] += len - 1;
  der[der_len - 2]     += len - 1;

  // and prepare our hash context
  SHA1_Init(ctx);
  SHA1_Update(ctx, der, der_len - 1);

  return rsa;
}

uint8_t sane_key(RSA *rsa) { // checks sanity of a RSA key (PKCS#1 v2.1)
  uint8_t sane = 1;

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *p1     = BN_CTX_get(ctx), // p - 1
         *q1     = BN_CTX_get(ctx), // q - 1
         *chk    = BN_CTX_get(ctx), // storage to run checks with
         *gcd    = BN_CTX_get(ctx), // GCD(p - 1, q - 1)
         *lambda = BN_CTX_get(ctx); // LCM(p - 1, q - 1)
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_sub(p1, rsa->p, BN_value_one()); // p - 1
    BN_sub(q1, rsa->q, BN_value_one()); // q - 1
  #else
    const BIGNUM *p_rsa;
    const BIGNUM *q_rsa;
    RSA_get0_factors(rsa, &p_rsa, &q_rsa);
    BN_sub(p1, p_rsa, BN_value_one()); // p - 1
    BN_sub(q1, q_rsa, BN_value_one()); // q - 1
  #endif
  BN_gcd(gcd, p1, q1, ctx);           // gcd(p - 1, q - 1)
  BN_lcm(lambda, p1, q1, gcd, ctx);   // lambda(n)

  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_gcd(chk, lambda, rsa->e, ctx); // check if e is coprime to lambda(n)
  #else
    const BIGNUM *e_rsa;
    RSA_get0_key(rsa, NULL, &e_rsa, NULL);
    BN_gcd(chk, lambda, e_rsa, ctx); // check if e is coprime to lambda(n) 
  #endif
  if(!BN_is_one(chk))
    sane = 0;

  // check if public exponent e is less than n - 1
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_sub(chk, rsa->e, rsa->n); // subtract n from e to avoid checking BN_is_zero
  #else
    const BIGNUM *n_rsa;
    RSA_get0_key(rsa, &n_rsa, &e_rsa, NULL);
    BN_sub(chk, &e_rsa, &n_rsa); // subtract n from e to avoid checking BN_is_zero
  #endif
  
  #if OPENSSL_VERSION_NUMBER < 0x10100000L
  if(!chk->neg)
    sane = 0;
  #else
  if(!BN_is_negative(chk))
    sane = 0;
  #endif

  #if OPENSSL_VERSION_NUMBER < 0x10100000L
    BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);    // d
    BN_mod(rsa->dmp1, rsa->d, p1, ctx);             // d mod (p - 1)
    BN_mod(rsa->dmq1, rsa->d, q1, ctx);             // d mod (q - 1)
    BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx); // q ^ -1 mod p
  #else
    const BIGNUM *d_rsa;
    const BIGNUM *dmp1_rsa;
    const BIGNUM *dmq1_rsa;
    const BIGNUM *iqmp_rsa;
    RSA_get0_key(rsa, NULL, &e_rsa, &d_rsa);
    RSA_get0_factors(rsa, &p_rsa, &q_rsa);
    RSA_get0_crt_params(rsa, &dmp1_rsa, &dmq1_rsa, &iqmp_rsa);
    BN_mod_inverse(&d_rsa, &e_rsa, lambda, ctx);    // d
    BN_mod(&dmp1_rsa, &d_rsa, p1, ctx);             // d mod (p - 1)
    BN_mod(&dmq1_rsa, &d_rsa, q1, ctx);             // d mod (q - 1)
    BN_mod_inverse(&iqmp_rsa, &q_rsa, &p_rsa, ctx); // q ^ -1 mod p
  #endif
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  // this is excessive but you're better off safe than (very) sorry
  // in theory this should never be true unless I made a mistake ;)
  if((RSA_check_key(rsa) != 1) && sane) {
    fprintf(stderr, "WARNING: Key looked okay, but OpenSSL says otherwise!\n");
    sane = 0;
  }

  return sane;
}

