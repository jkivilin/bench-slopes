/* bench-slope-nettle.c - libgcrypt style benchmark for libnettle
 * Copyright © 2016-2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
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

#ifndef HAVE_LIBNETTLE

int main(void)
{
  fprintf(stderr, "Missing libnettle\n");
  return 0;
}

#else /* HAVE_LIBNETTLE */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "slope.h"

#include <nettle/nettle-meta.h>
#include <nettle/cbc.h>
#include <nettle/ctr.h>
#include <nettle/blowfish.h>
#include <nettle/des.h>
#include <nettle/arcfour.h>
#include <nettle/salsa20.h>
#include <nettle/chacha.h>

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define PGM "bench-slope-nettle"


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  const char *name;
  struct bench_ops *ops;
  const char *aead_name;

  int algo;
};

struct cipher_ctx_s
{
  union
  {
    const struct nettle_cipher *c;
    const struct nettle_aead *aead;
  };
  void *iv;
  unsigned char ctx[] __attribute__((aligned(32)));
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

static const struct nettle_cipher * const nettle_ciphers2[] =
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

static struct cipher_ctx_s *cipher_open(int algo)
{
  const struct nettle_cipher *c = cipher_algo(algo);
  struct cipher_ctx_s *ctx;

  ctx = calloc(1, sizeof(*ctx) + c->context_size);
  if (!ctx)
    return NULL;

  ctx->c = c;

  ctx->iv = calloc(1, c->block_size + 1);
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
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = cipher_open (mode->algo);
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
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  obj->priv = hd;

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
  struct cipher_ctx_s *hd = obj->priv;

  free (hd->iv);
  free (hd);
}

static void
bench_ecb_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct cipher_ctx_s *hd = obj->priv;

  hd->c->encrypt (&hd->ctx, buflen, buf, buf);
}

static void
bench_ecb_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct cipher_ctx_s *hd = obj->priv;

  hd->c->decrypt (&hd->ctx, buflen, buf, buf);
}

static void
bench_cbc_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct cipher_ctx_s *hd = obj->priv;

  cbc_encrypt (&hd->ctx, hd->c->encrypt, hd->c->block_size, hd->iv,
	       buflen, buf, buf);
}

static void
bench_cbc_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct cipher_ctx_s *hd = obj->priv;

  cbc_decrypt (&hd->ctx, hd->c->decrypt, hd->c->block_size, hd->iv,
	       buflen, buf, buf);
}

static void
bench_ctr_crypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct cipher_ctx_s *hd = obj->priv;

  ctr_crypt (&hd->ctx, hd->c->encrypt, hd->c->block_size, hd->iv,
	     buflen, buf, buf);
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

static struct bench_ops ctr_crypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_ctr_crypt_do_bench
};


static const struct nettle_aead *cipher_algo_aead(const struct nettle_cipher *c,
						  const char *aead_name)
{
  const struct nettle_aead * const *aead;
  char buf1[32];
  char buf2[32];

  snprintf(buf1, sizeof(buf1), "%s_%s", aead_name, c->name);
  snprintf(buf2, sizeof(buf2), "%s_%s", c->name, aead_name);

  for (aead = nettle_aeads; *aead; aead++)
    {
      if (strcmp(buf1, (*aead)->name) == 0)
	return *aead;
      if (strcmp(buf2, (*aead)->name) == 0)
	return *aead;
    }

  return NULL;
}

static struct cipher_ctx_s *aead_open(const struct nettle_aead *aead)
{
  struct cipher_ctx_s *ctx;

  ctx = calloc(1, sizeof(*ctx) + aead->context_size);
  if (!ctx)
    return NULL;

  ctx->aead = aead;

  ctx->iv = calloc(1, 1);
  if (!ctx->iv)
    {
      free(ctx);
      return NULL;
    }

  return ctx;
}

static int
bench_aead_crypt_init (struct bench_obj *obj, int encrypt)
{
  struct bench_cipher_mode *mode = obj->priv;
  const struct nettle_cipher *c = cipher_algo(mode->algo);
  const struct nettle_aead *aead = cipher_algo_aead(c, mode->aead_name);
  struct cipher_ctx_s *hd;
  int keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = aead_open (aead);
  if (!hd)
    {
      fprintf (stderr, PGM ": error opening AEAD cipher `%s'\n",
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
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       cipher_algo_name (mode->algo));
      exit (1);
    }

  obj->priv = hd;

  return 0;
}

static int
bench_aead_encrypt_init (struct bench_obj *obj)
{
  return bench_aead_crypt_init(obj, 1);
}

static int
bench_aead_decrypt_init (struct bench_obj *obj)
{
  return bench_aead_crypt_init(obj, 0);
}

static void
bench_aead_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen,
			     const unsigned char *nonce, size_t noncelen)
{
  struct cipher_ctx_s *hd = obj->priv;
  const struct nettle_aead *aead = hd->aead;
  unsigned char tag[aead->digest_size];

  aead->set_nonce (&hd->ctx, nonce);
  aead->encrypt (&hd->ctx, buflen, buf, buf);
  aead->digest (&hd->ctx, sizeof(tag), tag);
}

static void
bench_aead_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen,
			     const unsigned char *nonce, size_t noncelen)
{
  struct cipher_ctx_s *hd = obj->priv;
  const struct nettle_aead *aead = hd->aead;
  unsigned char tag[aead->digest_size];

  aead->set_nonce (&hd->ctx, nonce);
  aead->decrypt (&hd->ctx, buflen, buf, buf);
  aead->digest (&hd->ctx, sizeof(tag), tag);
}

static void
bench_aead_authenticate_do_bench (struct bench_obj *obj, void *buf,
				  size_t buflen, const unsigned char *nonce,
				  size_t noncelen)
{
  struct cipher_ctx_s *hd = obj->priv;
  const struct nettle_aead *aead = hd->aead;
  unsigned char tag[aead->digest_size];
  unsigned char data = 0xff;

  aead->set_nonce (&hd->ctx, nonce);
  aead->update (&hd->ctx, buflen, buf);
  aead->encrypt (&hd->ctx, sizeof (data), &data, &data);
  aead->digest (&hd->ctx, sizeof(tag), tag);
}


static void
bench_gcm_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops gcm_encrypt_ops = {
  &bench_aead_encrypt_init,
  &bench_crypt_free,
  &bench_gcm_encrypt_do_bench
};

static struct bench_ops gcm_decrypt_ops = {
  &bench_aead_decrypt_init,
  &bench_crypt_free,
  &bench_gcm_decrypt_do_bench
};

static struct bench_ops gcm_authenticate_ops = {
  &bench_aead_encrypt_init,
  &bench_crypt_free,
  &bench_gcm_authenticate_do_bench
};


static void
bench_poly1305_encrypt_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_poly1305_decrypt_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_poly1305_authenticate_do_bench (struct bench_obj *obj, void *buf,
				      size_t buflen)
{
  static const unsigned char nonce[16] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xc9, 0xf8, 0xb7, 0xb6, 0xf5, 0xc4, 0xd3, 0xa2 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops poly1305_encrypt_ops = {
  &bench_aead_encrypt_init,
  &bench_crypt_free,
  &bench_poly1305_encrypt_do_bench
};

static struct bench_ops poly1305_decrypt_ops = {
  &bench_aead_decrypt_init,
  &bench_crypt_free,
  &bench_poly1305_decrypt_do_bench
};

static struct bench_ops poly1305_authenticate_ops = {
  &bench_aead_encrypt_init,
  &bench_crypt_free,
  &bench_poly1305_authenticate_do_bench
};


static struct bench_cipher_mode cipher_modes[] = {
  {"ECB enc", &ecb_encrypt_ops, NULL},
  {"ECB dec", &ecb_decrypt_ops, NULL},
  {"CBC enc", &cbc_encrypt_ops, NULL},
  {"CBC dec", &cbc_decrypt_ops, NULL},
  {"CTR enc", &ctr_crypt_ops, NULL},
  {"CTR dec", &ctr_crypt_ops, NULL},
  {"GCM enc", &gcm_encrypt_ops, "gcm"},
  {"GCM dec", &gcm_decrypt_ops, "gcm"},
  {"GCM auth", &gcm_authenticate_ops, "gcm"},
  {"POLY1305 enc", &poly1305_encrypt_ops, "poly1305"},
  {"POLY1305 dec", &poly1305_decrypt_ops, "poly1305"},
  {"POLY1305 auth", &poly1305_authenticate_ops, "poly1305"},
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

  /* Stream cipher? Only test with "ECB" or "POLY1305". */
  if (blklen == 1 && (strncmp(mode.name, "ECB", 3) != 0 &&
		      strncmp(mode.name, "POLY1305", 8) != 0))
    return;
  if (blklen == 1 && strncmp(mode.name, "ECB", 3) == 0)
    {
      mode.name = mode.ops == &ecb_encrypt_ops ? "STREAM enc" : "STREAM dec";
    }

  /* AEAD? check for corresponding nettle_aead. */
  if (mode.aead_name && cipher_algo_aead(c, mode.aead_name) == NULL)
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

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
};

struct md_ctx_s
{
  const struct nettle_hash *h;
  unsigned char ctx[] __attribute__((aligned(32)));
};

static const struct nettle_hash * const nettle_hashes2[] =
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

  obj->priv = hd;

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct md_ctx_s *hd = obj->priv;

  free(hd);
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct md_ctx_s *hd = obj->priv;
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


int
main (int argc, char **argv)
{
  static const struct bench_group groups[] =
    {
      { "hash", hash_bench },
      { "cipher", cipher_bench },
      { NULL, NULL }
    };

  return slope_main_template(argc, argv, groups, PGM);
}

#endif /* HAVE_LIBNETTLE */
