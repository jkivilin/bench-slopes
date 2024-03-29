/* bench-slope-nettle.c - libgcrypt style benchmark for libnettle
 * Copyright © 2016-2023 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Bench-slopes.
 *
 * Bench-slopes is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Bench-slopes is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>

#if defined(HAVE_CONFIG_H) && !defined(HAVE_LIBNETTLE)

int main(void)
{
  fprintf(stderr, "Missing libnettle\n");
  return 0;
}

#else /* HAVE_LIBNETTLE */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#ifdef HAVE_DLSYM
#include <dlfcn.h>
#endif

#include "slope.h"

#include <nettle/version.h>
#define HEADER_NETTLE_VERSION (100*NETTLE_VERSION_MAJOR + NETTLE_VERSION_MINOR)
#include <nettle/nettle-meta.h>
#include <nettle/cbc.h>
#include <nettle/cfb.h>
#include <nettle/ctr.h>
#include <nettle/xts.h>
#include <nettle/gcm.h>
#include <nettle/eax.h>
#include <nettle/blowfish.h>
#include <nettle/des.h>
#include <nettle/arcfour.h>
#include <nettle/salsa20.h>
#include <nettle/chacha.h>
#include <nettle/chacha-poly1305.h>
#if HEADER_NETTLE_VERSION >= 309
#include <nettle/ocb.h>
#include <nettle/siv-gcm.h>
#endif

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define LIBNAME "nettle"
#define PGM "bench-slope-" LIBNAME

/************************************ Old header forward compatibility hacks. */

#if HEADER_NETTLE_VERSION < 308
void (* cbc_aes128_encrypt)(const struct aes128_ctx *ctx, uint8_t *iv,
			    size_t length, uint8_t *dst, const uint8_t *src);
void (* cbc_aes192_encrypt)(const struct aes192_ctx *ctx, uint8_t *iv,
			    size_t length, uint8_t *dst, const uint8_t *src);
void (* cbc_aes256_encrypt)(const struct aes256_ctx *ctx, uint8_t *iv,
			    size_t length, uint8_t *dst, const uint8_t *src);

static void
compat_prepare_cbc_aes_encrypt(void)
{
#ifdef HAVE_DLSYM
  cbc_aes128_encrypt = dlsym(NULL, "nettle_cbc_aes128_encrypt");
  cbc_aes192_encrypt = dlsym(NULL, "nettle_cbc_aes192_encrypt");
  cbc_aes256_encrypt = dlsym(NULL, "nettle_cbc_aes256_encrypt");
#endif
}

#else /* HEADER_NETTLE_VERSION < 308 */

static void
compat_prepare_cbc_aes_encrypt(void)
{
}

#endif /* HEADER_NETTLE_VERSION < 308 */

#if HEADER_NETTLE_VERSION < 309

#define OCB_BLOCK_SIZE 16
#define OCB_DIGEST_SIZE 16
#define OCB_MAX_NONCE_SIZE 15

struct ocb_key {
  /* L_*, L_$ and L_0, and one reserved entry */
  union nettle_block16 L[4];
};

void (* ocb_set_key)(struct ocb_key *key, const void *encrypt_ctx,
		     nettle_cipher_func *f);
void (* ocb_encrypt_message)(const struct ocb_key *ocb_key,
			     const void *encrypt_ctx, nettle_cipher_func *f,
			     size_t nlength, const uint8_t *nonce,
			     size_t alength, const uint8_t *adata,
			     size_t tlength,
			     size_t clength, uint8_t *dst, const uint8_t *src);

int (* ocb_decrypt_message)(const struct ocb_key *ocb_key,
			    const void *encrypt_ctx, nettle_cipher_func *en_f,
			    const void *decrypt_ctx, nettle_cipher_func *de_f,
			    size_t nlength, const uint8_t *nonce,
			    size_t alength, const uint8_t *adata,
			    size_t tlength,
			    size_t mlength, uint8_t *dst, const uint8_t *src);

static void
compat_prepare_ocb(void)
{
#ifdef HAVE_DLSYM
  ocb_set_key = dlsym(NULL, "nettle_ocb_set_key");
  ocb_encrypt_message = dlsym(NULL, "nettle_ocb_encrypt_message");
  ocb_decrypt_message = dlsym(NULL, "nettle_ocb_decrypt_message");
#endif
}

#else /* HEADER_NETTLE_VERSION < 309 */

static void
compat_prepare_ocb(void)
{
}

#endif /* HEADER_NETTLE_VERSION < 309 */

#if HEADER_NETTLE_VERSION < 309

#define SIV_GCM_BLOCK_SIZE 16
#define SIV_GCM_DIGEST_SIZE 16
#define SIV_GCM_NONCE_SIZE 12

void (* siv_gcm_encrypt_message)(const struct nettle_cipher *nc,
				 const void *ctx, void *ctr_ctx,
				 size_t nlength, const uint8_t *nonce,
				 size_t alength, const uint8_t *adata,
				 size_t clength, uint8_t *dst,
				 const uint8_t *src);

int (* siv_gcm_decrypt_message)(const struct nettle_cipher *nc,
				const void *ctx, void *ctr_ctx,
				size_t nlength, const uint8_t *nonce,
				size_t alength, const uint8_t *adata,
				size_t mlength, uint8_t *dst,
				const uint8_t *src);

static void
compat_prepare_siv_gcm(void)
{
#ifdef HAVE_DLSYM
  siv_gcm_encrypt_message = dlsym(NULL, "nettle_siv_gcm_encrypt_message");
  siv_gcm_decrypt_message = dlsym(NULL, "nettle_siv_gcm_decrypt_message");
#endif
}

#else /* HEADER_NETTLE_VERSION < 309 */

static void
compat_prepare_siv_gcm(void)
{
}

#endif /* HEADER_NETTLE_VERSION < 309 */

/********************************************************* Cipher benchmarks. */

struct cipher_ctx_s
{
  const struct nettle_cipher *c;
  void *iv;
  uint64_t align64;
  unsigned char ctx[];
};

struct bench_cipher_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
  struct cipher_ctx_s *hd;
};


static const struct nettle_cipher nettle_blowfish128 =
  { "blowfish", sizeof(struct blowfish_ctx),
    8, 16,
    (nettle_set_key_func *) blowfish128_set_key,
    (nettle_set_key_func *) blowfish128_set_key,
    (nettle_cipher_func *) blowfish_encrypt,
    (nettle_cipher_func *) blowfish_decrypt
  };

static const struct nettle_cipher nettle_des3 =
  { "des3", sizeof(struct des3_ctx),
    8, 24,
    (nettle_set_key_func *) des3_set_key,
    (nettle_set_key_func *) des3_set_key,
    (nettle_cipher_func *) des3_encrypt,
    (nettle_cipher_func *) des3_decrypt
  };

static const struct nettle_cipher nettle_arcfour128 =
  { "arcfour", sizeof(struct arcfour_ctx),
    0, 16,
    (nettle_set_key_func *) arcfour128_set_key,
    (nettle_set_key_func *) arcfour128_set_key,
    (nettle_cipher_func *) arcfour_crypt,
    (nettle_cipher_func *) arcfour_crypt
  };

static const struct nettle_cipher nettle_salsa20 =
  { "salsa20", sizeof(struct salsa20_ctx),
    0, 32,
    (nettle_set_key_func *) salsa20_256_set_key,
    (nettle_set_key_func *) salsa20_256_set_key,
    (nettle_cipher_func *) salsa20_crypt,
    (nettle_cipher_func *) salsa20_crypt
  };

static const struct nettle_cipher nettle_salsa20r12 =
  { "salsa20r12", sizeof(struct salsa20_ctx),
    0, 32,
    (nettle_set_key_func *) salsa20_256_set_key,
    (nettle_set_key_func *) salsa20_256_set_key,
    (nettle_cipher_func *) salsa20r12_crypt,
    (nettle_cipher_func *) salsa20r12_crypt
  };

static const struct nettle_cipher nettle_chacha =
  { "chacha", sizeof(struct chacha_ctx),
    0, 32,
    (nettle_set_key_func *) chacha_set_key,
    (nettle_set_key_func *) chacha_set_key,
    (nettle_cipher_func *) chacha_crypt,
    (nettle_cipher_func *) chacha_crypt
  };

static const struct nettle_cipher * const nettle_ciphers_extra[] =
{
  &nettle_aes128,
  &nettle_aes192,
  &nettle_aes256,
  &nettle_camellia128,
  &nettle_camellia192,
  &nettle_camellia256,
  &nettle_serpent128,
  &nettle_serpent192,
  &nettle_serpent256,
  &nettle_twofish128,
  &nettle_twofish192,
  &nettle_twofish256,
  &nettle_cast128,
  &nettle_blowfish128,
  &nettle_arctwo128,
  &nettle_des3,
  &nettle_arcfour128,
  &nettle_salsa20,
  &nettle_salsa20r12,
  &nettle_chacha,
  NULL
};

static const struct nettle_cipher **nettle_ciphers2;


static int cipher_map_name(const char *name)
{
  int i;
  const struct nettle_cipher * const *c;

  for (i = 1, c = nettle_ciphers2; *c; i++, c++)
    if (strcmp(name, (*c)->name) == 0)
      return i;

  return 0;
}

static const struct nettle_cipher *cipher_algo(int algo)
{
  int i;
  const struct nettle_cipher * const *c;

  for (i = 1, c = nettle_ciphers2; *c; i++, c++)
    if (i == algo)
      return *c;

  return NULL;
}

static const char *cipher_algo_name(int algo)
{
  const struct nettle_cipher *c = cipher_algo(algo);

  if (c)
    return c->name;

  return NULL;
}

static struct cipher_ctx_s *cipher_open(const struct nettle_cipher *c,
					unsigned int context_size,
					unsigned int iv_size)
{
  struct cipher_ctx_s *ctx;

  ctx = calloc(1, sizeof(*ctx) + context_size);
  if (!ctx)
    return NULL;

  ctx->c = c;

  ctx->iv = calloc(1, iv_size + !iv_size);
  if (!ctx->iv)
    {
      free(ctx);
      return NULL;
    }

  return ctx;
}

static int
bench_crypt_init (struct bench_obj *obj, int encrypt)
{
  struct bench_cipher_mode *mode = obj->priv;
  const struct nettle_cipher *c = cipher_algo(mode->algo);
  struct cipher_ctx_s *hd;
  bool is_xts = (strncmp(mode->name, "XTS", 3) == 0);
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = cipher_open (c, c->context_size + (is_xts * c->context_size),
		    c->block_size + 1);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  keylen = c->key_size;
  if (keylen)
    {
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      if (encrypt)
	c->set_encrypt_key(&hd->ctx, key);
      else
	c->set_decrypt_key(&hd->ctx, key);

      if (is_xts)
	{
	  for (i = 0; i < keylen; i++)
	    key[i] = 0x77 ^ (55 - i);

	  /* setup tweak context */
	  c->set_encrypt_key(&hd->ctx[hd->c->context_size], key);
	}
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static int
bench_encrypt_init (struct bench_obj *obj)
{
  return bench_crypt_init (obj, 1);
}

static int
bench_decrypt_init (struct bench_obj *obj)
{
  return bench_crypt_init (obj, 0);
}

static void
bench_crypt_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  free (hd->iv);
  free (hd);
}

static void
bench_ecb_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  hd->c->encrypt (&hd->ctx, buflen, buf, buf);
}

static void
bench_ecb_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  hd->c->decrypt (&hd->ctx, buflen, buf, buf);
}

static void
bench_cbc_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;

  if (strncmp (c->name, "aes", 3) == 0)
    {
      if (cbc_aes128_encrypt && strcmp (c->name + 3, "128") == 0)
	{
	  cbc_aes128_encrypt ((void *)&hd->ctx, hd->iv, buflen, buf, buf);
	  return;
	}
      else if (cbc_aes192_encrypt && strcmp (c->name + 3, "192") == 0)
	{
	  cbc_aes192_encrypt ((void *)&hd->ctx, hd->iv, buflen, buf, buf);
	  return;
	}
      else if (cbc_aes256_encrypt && strcmp (c->name + 3, "256") == 0)
	{
	  cbc_aes256_encrypt ((void *)&hd->ctx, hd->iv, buflen, buf, buf);
	  return;
	}
    }

  cbc_encrypt (&hd->ctx, c->encrypt, c->block_size, hd->iv, buflen, buf, buf);
}

static void
bench_cbc_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  cbc_decrypt (&hd->ctx, hd->c->decrypt, hd->c->block_size, hd->iv,
	       buflen, buf, buf);
}

static void
bench_cfb_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  cfb_encrypt (&hd->ctx, hd->c->encrypt, hd->c->block_size, hd->iv,
	       buflen, buf, buf);
}

static void
bench_cfb_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  cfb_decrypt (&hd->ctx, hd->c->decrypt, hd->c->block_size, hd->iv,
	       buflen, buf, buf);
}

static void
bench_ctr_crypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  ctr_crypt (&hd->ctx, hd->c->encrypt, hd->c->block_size, hd->iv,
	     buflen, buf, buf);
}

static void
bench_xts_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  xts_encrypt_message(&hd->ctx, &hd->ctx[hd->c->context_size],
		      hd->c->encrypt, hd->iv, buflen, buf, buf);
}

static void
bench_xts_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;

  xts_decrypt_message(&hd->ctx, &hd->ctx[hd->c->context_size],
		      hd->c->decrypt, hd->c->encrypt, hd->iv, buflen, buf, buf);
}

static struct bench_ops ecb_encrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_ecb_encrypt_do_bench
};

static struct bench_ops ecb_decrypt_ops = {
  &bench_decrypt_init,
  &bench_crypt_free,
  &bench_ecb_decrypt_do_bench
};

static struct bench_ops cbc_encrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_cbc_encrypt_do_bench
};

static struct bench_ops cbc_decrypt_ops = {
  &bench_decrypt_init,
  &bench_crypt_free,
  &bench_cbc_decrypt_do_bench
};

static struct bench_ops cfb_encrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_cfb_encrypt_do_bench
};

static struct bench_ops cfb_decrypt_ops = {
  &bench_decrypt_init,
  &bench_crypt_free,
  &bench_cfb_decrypt_do_bench
};

static struct bench_ops ctr_crypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_ctr_crypt_do_bench
};

static struct bench_ops xts_encrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_xts_encrypt_do_bench
};

static struct bench_ops xts_decrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_xts_decrypt_do_bench
};


static int
bench_chacha_poly1305_crypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  const struct nettle_cipher *c = cipher_algo(mode->algo);
  struct cipher_ctx_s *hd;
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = cipher_open (c, sizeof(struct chacha_poly1305_ctx), 0);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening AEAD cipher `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  keylen = c->key_size;
  if (keylen)
    {
      struct chacha_poly1305_ctx *ctx = (void *)hd->ctx;
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      chacha_poly1305_set_key(ctx, key);
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static void
bench_chacha_poly1305_encrypt_do_bench (struct bench_obj *obj, void *buf,
					size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  struct chacha_poly1305_ctx *ctx = (void *)hd->ctx;
  unsigned char tag[CHACHA_POLY1305_DIGEST_SIZE];

  chacha_poly1305_set_nonce (ctx, nonce);
  chacha_poly1305_encrypt (ctx, buflen, buf, buf);
  chacha_poly1305_digest (ctx, sizeof(tag), tag);
}

static void
bench_chacha_poly1305_decrypt_do_bench (struct bench_obj *obj, void *buf,
					size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  struct chacha_poly1305_ctx *ctx = (void *)hd->ctx;
  unsigned char tag[CHACHA_POLY1305_DIGEST_SIZE];

  chacha_poly1305_set_nonce (ctx, nonce);
  chacha_poly1305_decrypt (ctx, buflen, buf, buf);
  chacha_poly1305_digest (ctx, sizeof(tag), tag);
}

static void
bench_chacha_poly1305_authenticate_do_bench (struct bench_obj *obj, void *buf,
					     size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  struct chacha_poly1305_ctx *ctx = (void *)hd->ctx;
  unsigned char tag[CHACHA_POLY1305_DIGEST_SIZE];

  chacha_poly1305_set_nonce (ctx, nonce);
  chacha_poly1305_update (ctx, buflen, buf);
  chacha_poly1305_digest (ctx, sizeof(tag), tag);
}

static struct bench_ops chacha_poly1305_encrypt_ops = {
  &bench_chacha_poly1305_crypt_init,
  &bench_crypt_free,
  &bench_chacha_poly1305_encrypt_do_bench
};

static struct bench_ops chacha_poly1305_decrypt_ops = {
  &bench_chacha_poly1305_crypt_init,
  &bench_crypt_free,
  &bench_chacha_poly1305_decrypt_do_bench
};

static struct bench_ops chacha_poly1305_authenticate_ops = {
  &bench_chacha_poly1305_crypt_init,
  &bench_crypt_free,
  &bench_chacha_poly1305_authenticate_do_bench
};


static int
bench_gcm_eax_crypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  const struct nettle_cipher *c = cipher_algo(mode->algo);
  bool is_eax = strncmp(mode->name, "EAX", 3) == 0;
  struct cipher_ctx_s *hd;
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = cipher_open (c, c->context_size + (is_eax ? sizeof(struct eax_key)
						 : sizeof(struct gcm_key)), 0);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }
  else
    {
      keylen = c->key_size;
      if (keylen)
	{
	  unsigned char *cipher_ctx = &hd->ctx[0];
	  unsigned char key[keylen];
	  int i;

	  for (i = 0; i < keylen; i++)
	    key[i] = 0x33 ^ (11 - i);

	  c->set_encrypt_key(cipher_ctx, key);

	  if (is_eax)
	    {
	      struct eax_key *eax_key = (void *)&hd->ctx[c->context_size];

	      eax_set_key (eax_key, cipher_ctx, c->encrypt);
	    }
	  else
	    {
	      struct gcm_key *gcm_key = (void *)&hd->ctx[c->context_size];

	      gcm_set_key (gcm_key, cipher_ctx, c->encrypt);
	    }
	}
      else
	{
	  fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
		   cipher_algo_name (mode->algo));
	  exit (1);
	}
    }

  mode->hd = hd;

  return 0;
}

static void
bench_gcm_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct gcm_key *gcm_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct gcm_ctx gctx;

  gcm_set_iv (&gctx, gcm_key, sizeof(nonce), nonce);
  gcm_encrypt (&gctx, gcm_key, cipher_ctx, c->encrypt, buflen, buf, buf);
  gcm_digest (&gctx, gcm_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static void
bench_gcm_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct gcm_key *gcm_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct gcm_ctx gctx;

  gcm_set_iv (&gctx, gcm_key, sizeof(nonce), nonce);
  gcm_decrypt (&gctx, gcm_key, cipher_ctx, c->encrypt, buflen, buf, buf);
  gcm_digest (&gctx, gcm_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static void
bench_gcm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct gcm_key *gcm_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct gcm_ctx gctx;

  gcm_set_iv (&gctx, gcm_key, sizeof(nonce), nonce);
  gcm_update (&gctx, gcm_key, buflen, buf);
  gcm_digest (&gctx, gcm_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static struct bench_ops gcm_encrypt_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_gcm_encrypt_do_bench
};

static struct bench_ops gcm_decrypt_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_gcm_decrypt_do_bench
};

static struct bench_ops gcm_authenticate_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_gcm_authenticate_do_bench
};


static void
bench_eax_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct eax_key *eax_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct eax_ctx ectx;

  eax_set_nonce (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(nonce), nonce);
  eax_encrypt (&ectx, eax_key, cipher_ctx, c->encrypt, buflen, buf, buf);
  eax_digest (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static void
bench_eax_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct eax_key *eax_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct eax_ctx ectx;

  eax_set_nonce (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(nonce), nonce);
  eax_decrypt (&ectx, eax_key, cipher_ctx, c->encrypt, buflen, buf, buf);
  eax_digest (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static void
bench_eax_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const unsigned char *cipher_ctx = &hd->ctx[0];
  const struct eax_key *eax_key = (void *)&hd->ctx[c->context_size];
  unsigned char tag[GCM_DIGEST_SIZE];
  struct eax_ctx ectx;

  eax_set_nonce (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(nonce), nonce);
  eax_update (&ectx, eax_key, cipher_ctx, c->encrypt, buflen, buf);
  eax_digest (&ectx, eax_key, cipher_ctx, c->encrypt, sizeof(tag), tag);
}

static struct bench_ops eax_encrypt_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_eax_encrypt_do_bench
};

static struct bench_ops eax_decrypt_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_eax_decrypt_do_bench
};

static struct bench_ops eax_authenticate_ops = {
  &bench_gcm_eax_crypt_init,
  &bench_crypt_free,
  &bench_eax_authenticate_do_bench
};


static int
bench_ocb_crypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  const struct nettle_cipher *c = cipher_algo(mode->algo);
  struct cipher_ctx_s *hd;
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;
  obj->extra_alloc_size = OCB_DIGEST_SIZE;

  hd = cipher_open (c, sizeof(struct ocb_key) + c->context_size * 2, 0);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }
  else
    {
      struct ocb_key *ocb_key = (void *)&hd->ctx[0];
      unsigned char *encrypt_ctx = &hd->ctx[sizeof(struct ocb_key)];
      unsigned char *decrypt_ctx = &encrypt_ctx[c->context_size];

      keylen = c->key_size;
      if (keylen)
	{
	  unsigned char key[keylen];
	  int i;

	  for (i = 0; i < keylen; i++)
	    key[i] = 0x33 ^ (11 - i);

	  c->set_encrypt_key(encrypt_ctx, key);
	  c->set_decrypt_key(decrypt_ctx, key);
	  ocb_set_key (ocb_key, encrypt_ctx, c->encrypt);
	}
      else
	{
	  fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
		   cipher_algo_name (mode->algo));
	  exit (1);
	}
    }

  mode->hd = hd;

  return 0;
}

static void
bench_ocb_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const struct ocb_key *ocb_key = (void *)&hd->ctx[0];
  const unsigned char *encrypt_ctx = &hd->ctx[sizeof(struct ocb_key)];

  ocb_encrypt_message (ocb_key,
		       encrypt_ctx, c->encrypt,
		       sizeof(nonce), nonce,
		       0, NULL,
		       OCB_DIGEST_SIZE, buflen, buf, buf);
}

static void
bench_ocb_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const struct ocb_key *ocb_key = (void *)&hd->ctx[0];
  const unsigned char *encrypt_ctx = &hd->ctx[sizeof(struct ocb_key)];
  const unsigned char *decrypt_ctx = &encrypt_ctx[c->context_size];

  ocb_decrypt_message (ocb_key,
		       encrypt_ctx, c->encrypt,
		       decrypt_ctx, c->decrypt,
		       sizeof(nonce), nonce,
		       0, NULL,
		       OCB_DIGEST_SIZE,
		       buflen, buf, buf);
}

static void
bench_ocb_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  const struct ocb_key *ocb_key = (void *)&hd->ctx[0];
  const unsigned char *encrypt_ctx = &hd->ctx[sizeof(struct ocb_key)];

  ocb_encrypt_message (ocb_key,
		       encrypt_ctx, c->encrypt,
		       sizeof(nonce), nonce,
		       buflen, buf,
		       OCB_DIGEST_SIZE, OCB_DIGEST_SIZE, buf, NULL);
}


static struct bench_ops ocb_encrypt_ops = {
  &bench_ocb_crypt_init,
  &bench_crypt_free,
  &bench_ocb_encrypt_do_bench
};

static struct bench_ops ocb_decrypt_ops = {
  &bench_ocb_crypt_init,
  &bench_crypt_free,
  &bench_ocb_decrypt_do_bench
};

static struct bench_ops ocb_authenticate_ops = {
  &bench_ocb_crypt_init,
  &bench_crypt_free,
  &bench_ocb_authenticate_do_bench
};


static int
bench_siv_gcm_crypt_init (struct bench_obj *obj)
{
  obj->extra_alloc_size = SIV_GCM_DIGEST_SIZE;
  return bench_encrypt_init (obj);
}

static void
bench_siv_gcm_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  uint64_t ctr_ctx[(c->context_size + 7) / 8];

  siv_gcm_encrypt_message (c, hd->ctx, ctr_ctx, sizeof(nonce), nonce, 0, NULL,
			   buflen + SIV_GCM_DIGEST_SIZE, buf, buf);
}

static void
bench_siv_gcm_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  uint64_t ctr_ctx[(c->context_size + 7) / 8];

  siv_gcm_decrypt_message (c, hd->ctx, ctr_ctx, sizeof(nonce), nonce, 0, NULL,
			   buflen, buf, buf);
}

static void
bench_siv_gcm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				     size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xc9, 0xf8, 0xb7, 0xb6 };
  struct bench_cipher_mode *mode = obj->priv;
  struct cipher_ctx_s *hd = mode->hd;
  const struct nettle_cipher *c = hd->c;
  uint64_t ctr_ctx[(c->context_size + 7) / 8];
  unsigned char tag[SIV_GCM_DIGEST_SIZE] = { 0 };

  siv_gcm_encrypt_message (c, hd->ctx, ctr_ctx, sizeof(nonce), nonce, buflen,
			   buf, SIV_GCM_DIGEST_SIZE, tag, tag);
}


static struct bench_ops siv_gcm_encrypt_ops = {
  &bench_siv_gcm_crypt_init,
  &bench_crypt_free,
  &bench_siv_gcm_encrypt_do_bench
};

static struct bench_ops siv_gcm_decrypt_ops = {
  &bench_siv_gcm_crypt_init,
  &bench_crypt_free,
  &bench_siv_gcm_decrypt_do_bench
};

static struct bench_ops siv_gcm_authenticate_ops = {
  &bench_siv_gcm_crypt_init,
  &bench_crypt_free,
  &bench_siv_gcm_authenticate_do_bench
};


static struct bench_cipher_mode cipher_modes[] = {
  {"ECB enc", &ecb_encrypt_ops},
  {"ECB dec", &ecb_decrypt_ops},
  {"CBC enc", &cbc_encrypt_ops},
  {"CBC dec", &cbc_decrypt_ops},
  {"CFB enc", &cfb_encrypt_ops},
  {"CFB dec", &cfb_decrypt_ops},
  {"CTR enc", &ctr_crypt_ops},
  {"CTR dec", &ctr_crypt_ops},
  {"XTS enc", &xts_encrypt_ops},
  {"XTS dec", &xts_decrypt_ops},
  {"GCM enc", &gcm_encrypt_ops},
  {"GCM dec", &gcm_decrypt_ops},
  {"GCM auth", &gcm_authenticate_ops},
  {"EAX enc", &eax_encrypt_ops},
  {"EAX dec", &eax_decrypt_ops},
  {"EAX auth", &eax_authenticate_ops},
  {"OCB enc", &ocb_encrypt_ops },
  {"OCB dec", &ocb_decrypt_ops },
  {"OCB auth", &ocb_authenticate_ops },
  {"GCM-SIV enc", &siv_gcm_encrypt_ops },
  {"GCM-SIV dec", &siv_gcm_decrypt_ops },
  {"GCM-SIV auth", &siv_gcm_authenticate_ops },
  {"POLY1305 enc", &chacha_poly1305_encrypt_ops},
  {"POLY1305 dec", &chacha_poly1305_decrypt_ops},
  {"POLY1305 auth", &chacha_poly1305_authenticate_ops},
  {0},
};


static void
cipher_bench_one (int algo, struct bench_cipher_mode *pmode)
{
  const struct nettle_cipher *c = cipher_algo(algo);
  struct bench_cipher_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;
  unsigned int blklen;

  mode.algo = algo;

  blklen = c->block_size ? c->block_size : 1;

  /* OCB? Only test 128-bit block ciphers. */
  if (strncmp(mode.name, "OCB", 3) == 0 && blklen != 16)
    return;

  /* OCB? Check if supported by loaded library. */
  if (strncmp(mode.name, "OCB", 3) == 0
      && ((uintptr_t)ocb_set_key == (uintptr_t)NULL
          || (uintptr_t)ocb_encrypt_message == (uintptr_t)NULL
          || (uintptr_t)ocb_decrypt_message == (uintptr_t)NULL))
    return;

  /* GCM-SIV? Only test 128-bit block ciphers. */
  if (strncmp(mode.name, "GCM-SIV", 7) == 0 && blklen != 16)
    return;

  /* GCM-SIV? Check if supported by loaded library. */
  if (strncmp(mode.name, "GCM-SIV", 7) == 0
      && ((uintptr_t)siv_gcm_encrypt_message == (uintptr_t)NULL
          || (uintptr_t)siv_gcm_decrypt_message == (uintptr_t)NULL))
    return;

  /* GCM? Only test 128-bit block ciphers. */
  if (strncmp(mode.name, "GCM", 3) == 0 && blklen != 16)
    return;

  /* EAX? Only test 128-bit block ciphers. */
  if (strncmp(mode.name, "EAX", 3) == 0 && blklen != 16)
    return;

  /* XTS? Only test 128-bit block ciphers. */
  if (strncmp(mode.name, "XTS", 3) == 0 && blklen != 16)
    return;

  /* Stream cipher? Only test with "ECB" or "POLY1305". */
  if (blklen == 1 && (strncmp(mode.name, "ECB", 3) != 0 &&
		      strncmp(mode.name, "POLY1305", 8) != 0))
    return;
  if (blklen == 1 && strncmp(mode.name, "ECB", 3) == 0)
    {
      mode.name = mode.ops == &ecb_encrypt_ops ? "STREAM enc" : "STREAM dec";
    }

  /* POLY1305? Only allowed for chacha cipher. */
  if (strncmp(mode.name, "POLY1305", 8) == 0 && strcmp(c->name, "chacha") != 0)
    return;

  bench_print_mode (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}


static void
_cipher_bench (int algo)
{
  const char *algoname;
  int i;

  algoname = cipher_algo_name (algo);

  bench_print_header (14, algoname);

  for (i = 0; cipher_modes[i].name; i++)
    cipher_bench_one (algo, &cipher_modes[i]);

  bench_print_footer (14);
}


void
cipher_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("cipher", "Cipher");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
        {
          algo = cipher_map_name (argv[i]);
          if (algo)
            _cipher_bench (algo);
        }
    }
  else
    {
      const struct nettle_cipher * const *c;

      for (i = 1, c = nettle_ciphers2; *c; i++, c++)
	_cipher_bench (i);
    }
}


/*********************************************************** Hash benchmarks. */

struct md_ctx_s
{
  const struct nettle_hash *h;
  uint64_t align64;
  unsigned char ctx[];
};

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
  struct md_ctx_s *hd;
};

static const struct nettle_hash * const nettle_hashes_extra[] =
{
  &nettle_md2,
  &nettle_md4,
  &nettle_md5,
  &nettle_gosthash94,
  &nettle_ripemd160,
  &nettle_sha1,
  &nettle_sha224,
  &nettle_sha256,
  &nettle_sha384,
  &nettle_sha512,
  &nettle_sha512_224,
  &nettle_sha512_256,
  &nettle_sha3_224,
  &nettle_sha3_256,
  &nettle_sha3_384,
  &nettle_sha3_512,
  NULL
};

static const struct nettle_hash **nettle_hashes2;


static int md_map_name(const char *name)
{
  int i;
  const struct nettle_hash * const *h;

  for (i = 1, h = nettle_hashes2; *h; i++, h++)
    if (strcmp(name, (*h)->name) == 0)
      return i;

  return 0;
}

static const struct nettle_hash *md_algo(int algo)
{
  int i;
  const struct nettle_hash * const *h;

  for (i = 1, h = nettle_hashes2; *h; i++, h++)
    if (i == algo)
      return *h;

  return NULL;
}

static const char *md_algo_name(int algo)
{
  const struct nettle_hash *h = md_algo(algo);

  if (h)
    return h->name;

  return NULL;
}


static struct md_ctx_s *md_open(int algo)
{
  const struct nettle_hash *h = md_algo(algo);
  struct md_ctx_s *md;

  md = calloc(1, sizeof(*md) + h->context_size);
  if (!md)
    return NULL;

  md->h = h;
  return md;
}


static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  struct md_ctx_s *hd;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = md_open (mode->algo);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n",
	       md_algo_name (mode->algo));
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  struct md_ctx_s *hd = mode->hd;

  free(hd);
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_hash_mode *mode = obj->priv;
  struct md_ctx_s *hd = mode->hd;
  unsigned char digest[1];
  void *ctx = hd->ctx;
  const struct nettle_hash *h = hd->h;

  h->init(ctx);
  h->update(ctx, buflen, buf);
  h->digest(ctx, sizeof(digest), digest);
}

static struct bench_ops hash_ops = {
  &bench_hash_init,
  &bench_hash_free,
  &bench_hash_do_bench
};


static struct bench_hash_mode hash_modes[] = {
  {"", &hash_ops},
  {0},
};


static void
hash_bench_one (int algo, struct bench_hash_mode *pmode)
{
  struct bench_hash_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-14, md_algo_name (algo));
  else
    bench_print_algo (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}


static void
_hash_bench (int algo)
{
  int i;

  for (i = 0; hash_modes[i].name; i++)
    hash_bench_one (algo, &hash_modes[i]);
}

void
hash_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("hash", "Hash");
  bench_print_header (14, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = md_map_name (argv[i]);
	  if (algo)
	    _hash_bench (algo);
	}
    }
  else
    {
      const struct nettle_hash * const *h;

      for (i = 1, h = nettle_hashes2; *h; i++, h++)
	_hash_bench (i);
    }

  bench_print_footer (14);
}


/************************************************************** Main program. */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int
count_pointers(const void * const *list)
{
  const void * const *p;
  int pos;

  for (pos = 0, p = list; *p; pos++, p++);

  return pos;
}

static void
combine_pointer_lists(const void **dst, int dst_size, const void * const *src)
{
  const void * const *p;
  const void * const *p2;
  int i, pos;

  for (pos = count_pointers(dst), i = 0, p = src; *p; i++, p++)
    {
      for (p2 = dst; *p2 && *p != *p2; p2++);

      if (!*p2 && pos < dst_size)
	dst[pos++] = *p;
    }

  dst[dst_size - 1] = NULL;
}

int
main (int argc, char **argv)
{
  static const struct bench_group groups[] =
    {
      { "hash", hash_bench },
      { "cipher", cipher_bench },
      { NULL, NULL }
    };
  int list_size;
  int ret;

  printf("%s: Nettle %d.%d\n", PGM,
         nettle_version_major(),
         nettle_version_minor());

  compat_prepare_cbc_aes_encrypt();
  compat_prepare_ocb();
  compat_prepare_siv_gcm();

  list_size = 1;
  list_size += count_pointers((const void * const *)nettle_ciphers_extra);
  list_size += count_pointers((const void * const *)nettle_ciphers);
  nettle_ciphers2 = calloc(list_size, sizeof(void *));
  combine_pointer_lists((const void **)nettle_ciphers2, list_size,
			(const void * const *)nettle_ciphers_extra);
  combine_pointer_lists((const void **)nettle_ciphers2, list_size,
			(const void * const *)nettle_ciphers);

  list_size = 1;
  list_size += count_pointers((const void * const *)nettle_hashes_extra);
  list_size += count_pointers((const void * const *)nettle_hashes);
  nettle_hashes2 = calloc(list_size, sizeof(void *));
  combine_pointer_lists((const void **)nettle_hashes2, list_size,
			(const void * const *)nettle_hashes_extra);
  combine_pointer_lists((const void **)nettle_hashes2, list_size,
			(const void * const *)nettle_hashes);

  ret = slope_main_template(argc, argv, groups, PGM, LIBNAME);
  free(nettle_ciphers2);
  free(nettle_hashes2);
  return ret;
}

#endif /* HAVE_LIBNETTLE */
