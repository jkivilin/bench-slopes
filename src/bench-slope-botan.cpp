/* bench-slope-botan.cpp - libgcrypt style benchmark for Botan
 * Copyright © 2018-2020 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#if defined(HAVE_CONFIG_H) && !defined(HAVE_BOTAN3) && !defined(HAVE_BOTAN2)

int main(void)
{
  fprintf(stderr, "Missing Botan\n");
  return 0;
}

#else /* HAVE_BOTAN3 || HAVE_BOTAN2 */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>

extern "C" {
#include "slope.h"
}

#include <botan/version.h>
#include <botan/secmem.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/aead.h>
#include <botan/hash.h>

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define LIBNAME "botan"
#define PGM "bench-slope-" LIBNAME


static Botan::Cipher_Dir
botan_cipher_dir (bool encrypt)
{
#ifdef HAVE_BOTAN3
  return encrypt ? Botan::Cipher_Dir::Encryption
		 : Botan::Cipher_Dir::Decryption;
#else
  return encrypt ? Botan::ENCRYPTION
		 : Botan::DECRYPTION;
#endif
}


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  const char *name;
  struct bench_ops *ops;
  const char *mode_name;

  char algo[32];
  std::unique_ptr<Botan::Cipher_Mode> cm;
  std::unique_ptr<Botan::AEAD_Mode> am;
  std::unique_ptr<Botan::StreamCipher> sc;
  unsigned int ivlen;
};

static int cipher_header_printed;

static const char * const botan_ciphers[] =
{
  "AES-128",
  "AES-192",
  "AES-256",
  "ARIA-128",
  "ARIA-192",
  "ARIA-256",
  "Blowfish",
  "CAST-128",
  "CAST-256",
  "Camellia-128",
  "Camellia-192",
  "Camellia-256",
  "3DES",
  "GOST-28147-89",
  "Noekeon",
  "SEED",
  "SM4",
  "Serpent",
  "Twofish",
  "ChaCha",
  "Salsa20",
  "RC4",
  NULL
};

static int
bench_crypt_cipher_mode_init (struct bench_obj *obj, int encrypt)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  int keylen;

  mode->cm = Botan::Cipher_Mode::create(mode->algo, botan_cipher_dir(encrypt));
  if (!mode->cm)
    return -1;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = mode->cm->key_spec().minimum_keylength();
  if (keylen)
    {
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      mode->cm->set_key(key, sizeof(key));
    }

  return 0;
}

static int
bench_encrypt_cipher_mode_init (struct bench_obj *obj)
{
  return bench_crypt_cipher_mode_init(obj, 1);
}

static int
bench_decrypt_cipher_mode_init (struct bench_obj *obj)
{
  return bench_crypt_cipher_mode_init(obj, 0);
}

static void
bench_crypt_cipher_mode_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  delete mode->cm.release();
}

static void
bench_crypt_cipher_mode_do_bench (struct bench_obj *obj, void *buf,
				  size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t iv[mode->cm->default_nonce_length()];

  memset(iv, 0, sizeof(iv));

  mode->cm->start(iv, sizeof(iv));
  mode->cm->process(reinterpret_cast<uint8_t *>(buf), buflen);
}

static struct bench_ops cipher_mode_encrypt_ops = {
  &bench_encrypt_cipher_mode_init,
  &bench_crypt_cipher_mode_free,
  &bench_crypt_cipher_mode_do_bench
};

static struct bench_ops cipher_mode_decrypt_ops = {
  &bench_decrypt_cipher_mode_init,
  &bench_crypt_cipher_mode_free,
  &bench_crypt_cipher_mode_do_bench
};


static int
bench_crypt_aead_mode_init (struct bench_obj *obj, int encrypt)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  int keylen;

  mode->am = Botan::AEAD_Mode::create(mode->algo, botan_cipher_dir(encrypt));
  if (!mode->am)
    return -1;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = mode->am->key_spec().minimum_keylength();
  if (keylen)
    {
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      mode->am->set_key(key, sizeof(key));
    }

  return 0;
}

static int
bench_encrypt_aead_mode_init (struct bench_obj *obj)
{
  return bench_crypt_aead_mode_init(obj, 1);
}

static int
bench_decrypt_aead_mode_init (struct bench_obj *obj)
{
  return bench_crypt_aead_mode_init(obj, 0);
}

static void
bench_crypt_aead_mode_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  delete mode->am.release();
}

static void
bench_encrypt_aead_mode_do_bench (struct bench_obj *obj, void *vbuf,
				  size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t iv[mode->am->default_nonce_length()];
  uint8_t *buf = reinterpret_cast<uint8_t *>(vbuf);
  size_t granularity = mode->am->update_granularity();

  memset(iv, 0, sizeof(iv));

  mode->am->start(iv, sizeof(iv));

  if ((buflen % granularity == 0 && buflen / granularity > 1) ||
      (buflen % granularity != 0 && buflen / granularity > 0))
  {
    size_t num_g = buflen / granularity - (buflen % granularity == 0);
    mode->am->process(buf, num_g * granularity);
    buf += num_g * granularity;
    buflen -= num_g * granularity;
  }

  Botan::secure_vector<uint8_t> tail(buf, buf + buflen);
  mode->am->finish(tail);
}

static void
bench_decrypt_aead_mode_do_bench (struct bench_obj *obj, void *vbuf,
				  size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t iv[mode->am->default_nonce_length()];
  uint8_t mac[mode->am->tag_size()];
  uint8_t *buf = reinterpret_cast<uint8_t *>(vbuf);
  size_t granularity = mode->am->update_granularity();

  memset(iv, 0, sizeof(iv));
  memset(mac, 0, sizeof(mac));

  mode->am->start(iv, sizeof(iv));

  if ((buflen % granularity == 0 && buflen / granularity > 1) ||
      (buflen % granularity != 0 && buflen / granularity > 0))
  {
    size_t num_g = buflen / granularity - (buflen % granularity == 0);
    mode->am->process(buf, num_g * granularity);
    buf += num_g * granularity;
    buflen -= num_g * granularity;
  }

  Botan::secure_vector<uint8_t> tail(buflen + sizeof(mac));
  tail.insert(tail.end(), buf, buf + buflen);
  tail.insert(tail.end(), mac, mac + sizeof(mac));
  try
  {
    mode->am->finish(tail);
  }
  catch(...)
  {
    /* tag/mac check always fails. */
  }
}

static void
bench_authenticate_aead_mode_do_bench (struct bench_obj *obj, void *vbuf,
				       size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t iv[mode->am->default_nonce_length()];
  uint8_t mac[mode->am->tag_size()];
  uint8_t *buf = reinterpret_cast<uint8_t *>(vbuf);

  memset(iv, 0, sizeof(iv));
  memset(mac, 0, sizeof(mac));

  mode->am->reset();
  mode->am->set_associated_data(buf, buflen);

  try
  {
    mode->am->start(iv, sizeof(iv));
    Botan::secure_vector<uint8_t> tail(sizeof(mac));
    tail.insert(tail.end(), mac, mac + sizeof(mac));
    mode->am->finish(tail);
  }
  catch(...)
  {
    /* tag/mac check always fails. */
  }
}

static struct bench_ops aead_mode_encrypt_ops = {
  &bench_encrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_encrypt_aead_mode_do_bench
};

static struct bench_ops aead_mode_decrypt_ops = {
  &bench_decrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_decrypt_aead_mode_do_bench
};

static struct bench_ops aead_mode_authenticate_ops = {
  &bench_decrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_authenticate_aead_mode_do_bench
};


static int
bench_crypt_stream_cipher_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  int keylen;
  int i;

  mode->sc = Botan::StreamCipher::create(mode->algo);
  if (!mode->sc)
    return -1;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = mode->sc->minimum_keylength();
  if (keylen)
    {
      unsigned char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      mode->sc->set_key(key, sizeof(key));
    }

  mode->ivlen = 0;
  for (i = 1; i <= 64; i++)
    {
      if (mode->sc->valid_iv_length(i))
	{
	  mode->ivlen = i;
	}
    }

  return 0;
}

static void
bench_crypt_stream_cipher_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  delete mode->sc.release();
}

static void
bench_crypt_stream_cipher_do_bench (struct bench_obj *obj, void *buf,
				size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  if (mode->ivlen > 0)
  {
    uint8_t iv[mode->ivlen];
    memset(iv, 0, sizeof(iv));
    mode->sc->set_iv(iv, sizeof(iv));
  }
  else
  {
    mode->sc->set_iv(NULL, 0);
  }

  mode->sc->cipher1(reinterpret_cast<uint8_t *>(buf), buflen);
}

static struct bench_ops stream_cipher_crypt_ops = {
  &bench_crypt_stream_cipher_init,
  &bench_crypt_stream_cipher_free,
  &bench_crypt_stream_cipher_do_bench
};


static const struct bench_cipher_mode block_cipher_modes[] = {
  {"CBC enc", &cipher_mode_encrypt_ops, "CBC"},
  {"CBC dec", &cipher_mode_decrypt_ops, "CBC"},
  {"CFB enc", &cipher_mode_encrypt_ops, "CFB"},
  {"CFB dec", &cipher_mode_decrypt_ops, "CFB"},
  {"OFB enc", &stream_cipher_crypt_ops, "OFB"},
  {"OFB dec", &stream_cipher_crypt_ops, "OFB"},
  {"CTR enc", &stream_cipher_crypt_ops, "CTR"},
  {"CTR dec", &stream_cipher_crypt_ops, "CTR"},
  {"XTS enc", &cipher_mode_encrypt_ops, "XTS"},
  {"XTS dec", &cipher_mode_decrypt_ops, "XTS"},
  {"GCM enc", &aead_mode_encrypt_ops, "GCM"},
  {"GCM dec", &aead_mode_decrypt_ops, "GCM"},
  {"GCM auth", &aead_mode_authenticate_ops, "GCM"},
  {"EAX enc", &aead_mode_encrypt_ops, "EAX"},
  {"EAX dec", &aead_mode_decrypt_ops, "EAX"},
  {"EAX auth", &aead_mode_authenticate_ops, "EAX"},
  {"OCB enc", &aead_mode_encrypt_ops, "OCB"},
  {"OCB dec", &aead_mode_decrypt_ops, "OCB"},
  {"OCB auth", &aead_mode_authenticate_ops, "OCB"},
  {0},
};

static void
cipher_bench_one (const char *algo, const struct bench_cipher_mode *pmode,
		  int plain_algo)
{
  struct bench_cipher_mode mode;
  struct bench_obj obj = { 0 };
  double result;

  memcpy(reinterpret_cast<void *>(&mode), pmode, sizeof(mode));

  if (plain_algo)
    snprintf(mode.algo, sizeof(mode.algo), "%s", algo);
  else if (mode.ops == &stream_cipher_crypt_ops)
    snprintf(mode.algo, sizeof(mode.algo), "%s(%s)", mode.mode_name, algo);
  else
    snprintf(mode.algo, sizeof(mode.algo), "%s/%s", algo, mode.mode_name);

  try
  {
    struct bench_cipher_mode mode_test;
    struct bench_obj obj_test = { .priv = &mode_test };
    static uint64_t tmpbuf[16];
    memcpy(reinterpret_cast<void *>(&mode_test), &mode, sizeof(mode));
    if (mode_test.ops->initialize(&obj_test) < 0)
      return;
    mode_test.ops->do_run(&obj_test, &tmpbuf, sizeof(tmpbuf));
    mode_test.ops->finalize(&obj_test);
  }
  catch (...)
  {
    return;
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
_block_cipher_bench (const char *algo)
{
  int i;

  cipher_header_printed = 0;

  for (i = 0; block_cipher_modes[i].name; i++)
    cipher_bench_one (algo, &block_cipher_modes[i], 0);

  if (cipher_header_printed)
    bench_print_footer (14);
}

static void
_stream_cipher_bench (const char *algo)
{
  struct bench_cipher_mode mode = {};

  cipher_header_printed = 0;

  mode.name = "STREAM enc/dec";
  mode.ops = &stream_cipher_crypt_ops;
  cipher_bench_one (algo, &mode, 1);
  if (strcmp(algo, "ChaCha") == 0)
    {
      mode.name = "POLY1305 enc";
      mode.ops = &aead_mode_encrypt_ops;
      cipher_bench_one ("ChaCha20Poly1305", &mode, 1);
      mode.name = "POLY1305 dec";
      mode.ops = &aead_mode_decrypt_ops;
      cipher_bench_one ("ChaCha20Poly1305", &mode, 1);
      mode.name = "POLY1305 auth";
      mode.ops = &aead_mode_authenticate_ops;
      cipher_bench_one ("ChaCha20Poly1305", &mode, 1);
    }

  if (cipher_header_printed)
    bench_print_footer (14);
}

static void
_cipher_bench (const char *algo)
{
  struct bench_cipher_mode mode = {};
  struct bench_obj obj_test = { .priv = &mode };

  /* Check if algo is stream cipher. */
  mode.name = "";
  snprintf(mode.algo, sizeof(mode.algo), "%s", algo);
  mode.ops = &stream_cipher_crypt_ops;

  if (mode.ops->initialize(&obj_test) < 0)
    {
      /* Not stream cipher, try as block cipher. */
      _block_cipher_bench(algo);
    }
  else
    {
      mode.ops->finalize(&obj_test);
      _stream_cipher_bench(algo);
    }
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
      for (i = 0; botan_ciphers[i]; i++)
	_cipher_bench (botan_ciphers[i]);
    }
}

/*********************************************************** Hash benchmarks. */

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  const char *algo;
  std::unique_ptr<Botan::HashFunction> hd;
};

static const char *botan_hashes[] =
{
  "BLAKE2b",
  "GOST-34.11",
  "Keccak-1600",
  "MD4",
  "MD5",
  "RIPEMD-160",
  "SHA-1",
  "SHA-224",
  "SHA-256",
  "SHA-384",
  "SHA-512",
  "SHA-3",
  "SHAKE-128",
  "SHAKE-256",
  "SM3",
  "Skein-512",
  "Streebog-256",
  "Streebog-512",
  "Whirlpool",
  "Adler32",
  "CRC24",
  "CRC32",
  NULL
};


static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  mode->hd = Botan::HashFunction::create(mode->algo);
  if (!mode->hd)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n",
	       mode->algo);
      exit (1);
    }

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);

  delete mode->hd.release();
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);
  Botan::secure_vector<uint8_t> digest;

  digest = mode->hd->process(reinterpret_cast<uint8_t *>(buf), buflen);
  (void)digest;
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
hash_bench_one (const char *algo, struct bench_hash_mode *pmode)
{
  struct bench_hash_mode mode;
  struct bench_obj obj = { 0 };
  double result;

  memcpy(reinterpret_cast<void *>(&mode), pmode, sizeof(mode));

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-14, algo);
  else
    bench_print_algo (14, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}


static void
_hash_bench (const char *algo)
{
  int i;

  for (i = 0; hash_modes[i].name; i++)
    hash_bench_one (algo, &hash_modes[i]);
}

void
hash_bench (char **argv, int argc)
{
  const char *algo;
  int i;

  bench_print_section ("hash", "Hash");
  bench_print_header (14, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = argv[i];
	  if (algo && Botan::HashFunction::create(algo))
	    _hash_bench (algo);
	}
    }
  else
    {
      for (i = 0; botan_hashes[i]; i++)
	{
	  algo = botan_hashes[i];
	  if (algo && Botan::HashFunction::create(algo))
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

  printf("%s: %s\n", PGM, Botan::version_string().c_str());

  return slope_main_template(argc, argv, groups, PGM, LIBNAME);
}

#endif /* HAVE_BOTAN3 */
