/* bench-slope-openssl.c - libgcrypt style benchmark for OpenSSL
 * Copyright © 2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#ifndef HAVE_OPENSSL

int main(void)
{
  fprintf(stderr, "Missing OpenSSL\n");
  return 0;
}

#else /* HAVE_OPENSSL */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "slope.h"

#include <openssl/evp.h>

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define PGM "bench-slope-openssl"


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  const char *name;
  struct bench_ops *ops;
  const char *mode_name;

  const EVP_CIPHER *algo;
  EVP_CIPHER_CTX hd;
  int init;
};

static int cipher_header_printed;

static const char * const openssl_ciphers[] =
{
  "idea",
  "des-ede3",
  "cast5",
  "bf",
  "aes-128",
  "aes-192",
  "aes-256",
  "rc4",
  "des",
  "rc2",
  "seed",
  "camellia-128",
  "camellia-192",
  "camellia-256",
  "aria-128",
  "aria-192",
  "aria-256",
  "chacha20",
  NULL
};


static int
bench_crypt_init (struct bench_obj *obj, int encrypt)
{
  struct bench_cipher_mode *mode = obj->priv;
  EVP_CIPHER_CTX *hd;
  int keylen;
  int ret = -1;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = EVP_CIPHER_key_length(mode->algo);
  if (keylen)
    {
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      if (encrypt)
	ret = EVP_EncryptInit_ex(&mode->hd, mode->algo, NULL, key, NULL);
      else
	ret = EVP_DecryptInit_ex(&mode->hd, mode->algo, NULL, key, NULL);

      if (ret)
	mode->init = 1;
    }

  if (ret != 1)
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       EVP_CIPHER_name (mode->algo));
      exit (1);
    }

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

  EVP_CIPHER_CTX_cleanup(&mode->hd);
}

static void
bench_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  unsigned int outlen = 0;
  unsigned int tmplen;
  char iv[16] = {};

  EVP_EncryptInit_ex(&mode->hd, NULL, NULL, NULL, iv);
  EVP_EncryptUpdate(&mode->hd, buf, &outlen, buf, buflen);
  if (outlen != buflen)
    EVP_EncryptFinal_ex(&mode->hd, buf + outlen, &tmplen);
}

static void
bench_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  unsigned int outlen = 0;
  unsigned int tmplen;
  char iv[16] = {};

  EVP_DecryptInit_ex(&mode->hd, NULL, NULL, NULL, iv);
  EVP_DecryptUpdate(&mode->hd, buf, &outlen, buf, buflen);
  if (outlen != buflen)
    EVP_DecryptFinal_ex(&mode->hd, buf + outlen, &tmplen);
}

static void
bench_authenticate_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  unsigned int outlen = 0;
  unsigned int tmplen;
  char iv[16] = {};

  EVP_EncryptInit_ex(&mode->hd, NULL, NULL, NULL, iv);
  EVP_EncryptUpdate(&mode->hd, NULL, &outlen, buf, buflen);
  if (outlen != buflen)
    EVP_EncryptFinal_ex(&mode->hd, buf, &tmplen);
}

static struct bench_ops encrypt_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_encrypt_do_bench
};

static struct bench_ops decrypt_ops = {
  &bench_decrypt_init,
  &bench_crypt_free,
  &bench_decrypt_do_bench
};

static struct bench_ops authenticate_ops = {
  &bench_encrypt_init,
  &bench_crypt_free,
  &bench_authenticate_do_bench
};


static const struct bench_cipher_mode cipher_modes[] = {
  {"ECB enc", &encrypt_ops, "ecb"},
  {"ECB dec", &decrypt_ops, "ecb"},
  {"CBC enc", &encrypt_ops, "cbc"},
  {"CBC dec", &decrypt_ops, "cbc"},
  {"CFB enc", &encrypt_ops, "cfb"},
  {"CFB dec", &decrypt_ops, "cfb"},
  {"OFB enc", &encrypt_ops, "ofb"},
  {"OFB dec", &decrypt_ops, "ofb"},
  {"CTR enc", &encrypt_ops, "ctr"},
  {"CTR dec", &decrypt_ops, "ctr"},
  {"XTS enc", &encrypt_ops, "xts"},
  {"XTS dec", &decrypt_ops, "xts"},
  {"GCM enc", &encrypt_ops, "gcm"},
  {"GCM dec", &decrypt_ops, "gcm"},
  {"GCM auth", &authenticate_ops, "gcm"},
  {"OCB enc", &encrypt_ops, "ocb"},
  {"OCB dec", &decrypt_ops, "ocb"},
  {"OCB auth", &authenticate_ops, "ocb"},
  {"POLY1305 enc", &encrypt_ops, "poly1305"},
  {"POLY1305 dec", &decrypt_ops, "poly1305"},
  {"POLY1305 auth", &authenticate_ops, "poly1305"},
  {0},
};


static void
cipher_bench_one (const char *algo, const struct bench_cipher_mode *pmode)
{
  char ecb_name[64];
  char cipher_name[64];
  const EVP_CIPHER *ecb_algo;
  struct bench_cipher_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;
  int blklen;

  snprintf(ecb_name, sizeof(ecb_name), "%s-ecb", algo);
  snprintf(cipher_name, sizeof(cipher_name), "%s-%s", algo, mode.mode_name);

  ecb_algo = EVP_get_cipherbyname(ecb_name);
  if (ecb_algo)
    {
      mode.algo = EVP_get_cipherbyname(cipher_name);
      if (!mode.algo)
	return;

      blklen = EVP_CIPHER_block_size(EVP_get_cipherbyname(ecb_name));
      blklen = blklen > 0 ? blklen : 1;
    }
  else
    {
      if (strncmp(mode.name, "ECB", 3) == 0)
	mode.algo = EVP_get_cipherbyname(algo);
      else
	mode.algo = EVP_get_cipherbyname(cipher_name);

      if (!mode.algo)
	return;

      blklen = EVP_CIPHER_block_size(mode.algo);
      blklen = blklen > 0 ? blklen : 1;
    }

  /* Stream cipher? Only test with "ECB" or "POLY1305". */
  if (blklen == 1 && (strncmp(mode.name, "ECB", 3) != 0 &&
		      strncmp(mode.name, "POLY1305", 8) != 0))
    return;
  if (blklen == 1 && strncmp(mode.name, "ECB", 3) == 0)
    {
      mode.name = strcmp(mode.name, "ECB enc") == 0
		    ? "STREAM enc" : "STREAM dec";
    }

  if (!cipher_header_printed)
    bench_print_header (14, algo);
  cipher_header_printed = 1;

  bench_print_mode (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}

static void
_cipher_bench (const char *algo)
{
  int i;

  cipher_header_printed = 0;

  for (i = 0; cipher_modes[i].name; i++)
    cipher_bench_one (algo, &cipher_modes[i]);

  if (cipher_header_printed)
    bench_print_footer (14);
}

void
cipher_bench (char **argv, int argc)
{
  int i;

  bench_print_section ("cipher", "Cipher");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	_cipher_bench (argv[i]);
    }
  else
    {
      for (i = 0; openssl_ciphers[i]; i++)
	_cipher_bench (openssl_ciphers[i]);
    }
}

/*********************************************************** Hash benchmarks. */

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  const EVP_MD *algo;
  EVP_MD_CTX *hd;
  unsigned int digestlen;
};

static const char *openssl_hashes[] =
{
  "md2",
  "md4",
  "md5",
  "blake2b512",
  "blake2s256",
  "sha1",
  "sha224",
  "sha256",
  "sha384",
  "sha512",
  "ripemd160",
  "whirlpool",
  NULL
};


static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  EVP_MD_CTX *hd;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  hd = EVP_MD_CTX_create();
  if (!hd || EVP_DigestInit_ex(hd, mode->algo, NULL) != 1)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n",
	       EVP_MD_name (mode->algo));
      exit (1);
    }

  mode->hd = hd;
  mode->digestlen = EVP_MD_size(mode->algo);

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;

  EVP_MD_CTX_destroy(mode->hd);
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_hash_mode *mode = obj->priv;
  unsigned char digest[mode->digestlen];
  unsigned int digest_len = sizeof(digest);

  EVP_DigestInit_ex(mode->hd, NULL, NULL);
  EVP_DigestUpdate(mode->hd, buf, buflen);
  EVP_DigestFinal_ex(mode->hd, digest, &digest_len);
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
hash_bench_one (const EVP_MD *algo, struct bench_hash_mode *pmode)
{
  struct bench_hash_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-14, EVP_MD_name (algo));
  else
    bench_print_algo (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}


static void
_hash_bench (const EVP_MD *algo)
{
  int i;

  for (i = 0; hash_modes[i].name; i++)
    hash_bench_one (algo, &hash_modes[i]);
}

void
hash_bench (char **argv, int argc)
{
  const EVP_MD *algo;
  int i;

  bench_print_section ("hash", "Hash");
  bench_print_header (14, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = EVP_get_digestbyname (argv[i]);
	  if (algo)
	    _hash_bench (algo);
	}
    }
  else
    {
      for (i = 0; openssl_hashes[i]; i++)
	{
	  algo = EVP_get_digestbyname (openssl_hashes[i]);
	  if (algo)
	    _hash_bench (algo);
	}
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

  printf("%s: %s\n", PGM, OPENSSL_VERSION_TEXT);

  OpenSSL_add_all_algorithms();

  return slope_main_template(argc, argv, groups, PGM);
}

#endif /* HAVE_OPENSSL */
