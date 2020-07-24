/* bench-slope-botan.cpp - libgcrypt style benchmark for Crypto++
 * Copyright © 2020 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#if defined(HAVE_CONFIG_H) && !defined(HAVE_CRYPTOPP)

int main(void)
{
  fprintf(stderr, "Missing Crypto++\n");
  return 0;
}

#else /* HAVE_CRYPTOPP */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <string.h>

extern "C" {
#include "slope.h"
}

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <cryptopp/cryptlib.h>
#include <cryptopp/factory.h>
#include <cryptopp/modes.h>
#include <cryptopp/seed.h>
#include <cryptopp/camellia.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/eax.h>
#include <cryptopp/twofish.h>
#include <cryptopp/serpent.h>
#include <cryptopp/cast.h>
#include <cryptopp/des.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/arc4.h>
#include <cryptopp/salsa.h>
#include <cryptopp/crc.h>
#include <cryptopp/md5.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#if CRYPTOPP_VERSION >= 600
#  define HAVE_SM3
#  define HAVE_SM4
#  include <cryptopp/sm3.h>
#  include <cryptopp/sm4.h>
#endif
#if CRYPTOPP_VERSION >= 700
#  define HAVE_CHACHA
#  include <cryptopp/chacha.h>
#endif
#if CRYPTOPP_VERSION >= 810
#  define HAVE_CHACHAPOLY
#  include <cryptopp/chachapoly.h>
#endif
#if CRYPTOPP_VERSION >= 800
#  define HAVE_BLAKE2
#  include <cryptopp/blake2.h>
#endif
#if CRYPTOPP_VERSION >= 830
#  define HAVE_XTS_MODE
#  include <cryptopp/xts.h>
#endif

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define LIBNAME "cryptopp"
#define PGM "bench-slope-" LIBNAME


template <class T, class Enable = void>
struct is_defined
{
    static constexpr bool value = false;
};

template <class T>
struct is_defined<T, std::enable_if_t<(sizeof(T) > 0)>>
{
    static constexpr bool value = true;
};


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  const char *name;
  struct bench_ops *ops;
  const char *mode_name;

  char algo[32];
  std::unique_ptr<CryptoPP::SymmetricCipher> sm;
  std::unique_ptr<CryptoPP::AuthenticatedSymmetricCipher> am;
  unsigned int ivlen;
};

enum bench_cipher_type
{
  BENCH_CIPHER_TYPE_BLOCK_CIPHER,
  BENCH_CIPHER_TYPE_STREAM_CIPHER,
};

static const uint8_t default_iv[32] =
{
  0,1,2,0,4,5,6,7,8,9,10,11,12,13,14,15,15,14,13,12,11,10,9,8,7,6,5,4,0,2,1,0
};

static std::list<std::tuple<std::string, enum bench_cipher_type>> cipher_algos;
static int cipher_header_printed;

template <class block_cipher>
void bench_register_block_cipher(void)
{
  cipher_algos.push_back(std::tuple<std::string, enum bench_cipher_type>(
    block_cipher::Encryption::StaticAlgorithmName(), BENCH_CIPHER_TYPE_BLOCK_CIPHER));
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::ECB_Mode<block_cipher>>();
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::CBC_Mode<block_cipher>>();
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::CFB_Mode<block_cipher>>();
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::OFB_Mode<block_cipher>>();
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::CTR_Mode<block_cipher>>();
#ifdef HAVE_XTS_MODE
  CryptoPP::RegisterSymmetricCipherDefaultFactories<CryptoPP::XTS_Mode<block_cipher>>();
#endif
  CryptoPP::RegisterAuthenticatedSymmetricCipherDefaultFactories<CryptoPP::GCM<block_cipher> >();
  CryptoPP::RegisterAuthenticatedSymmetricCipherDefaultFactories<CryptoPP::EAX<block_cipher> >();
}

template <class stream_cipher>
void bench_register_stream_cipher(void)
{
  cipher_algos.push_back(std::tuple<std::string, enum bench_cipher_type>(
    stream_cipher::Encryption::StaticAlgorithmName(), BENCH_CIPHER_TYPE_STREAM_CIPHER));
  CryptoPP::RegisterSymmetricCipherDefaultFactories<stream_cipher>();
}

static void bench_register_ciphers(void)
{
  bench_register_block_cipher<CryptoPP::AES>();
  bench_register_block_cipher<CryptoPP::Camellia>();
  bench_register_block_cipher<CryptoPP::Twofish>();
  bench_register_block_cipher<CryptoPP::Serpent>();
  bench_register_block_cipher<CryptoPP::SEED>();
#ifdef HAVE_SM4
  bench_register_block_cipher<CryptoPP::SM4>();
#endif
  bench_register_block_cipher<CryptoPP::DES_EDE3>();
  bench_register_block_cipher<CryptoPP::CAST128>();
  bench_register_block_cipher<CryptoPP::Blowfish>();

  bench_register_stream_cipher<CryptoPP::Weak::ARC4>();
  bench_register_stream_cipher<CryptoPP::Salsa20>();
#ifdef HAVE_CHACHA
  bench_register_stream_cipher<CryptoPP::ChaCha>();
#ifdef HAVE_CHACHAPOLY
  CryptoPP::RegisterAuthenticatedSymmetricCipherDefaultFactories<CryptoPP::ChaCha20Poly1305>();
#endif
#endif
}

template <int instance, int no_iv = 0>
static int
bench_crypt_symmetric_cipher_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  int keylen;
  int ivlen;

  try
    {
      mode->sm = std::unique_ptr<CryptoPP::SymmetricCipher>(
	CryptoPP::ObjectFactoryRegistry<CryptoPP::SymmetricCipher, instance>::
	  Registry().CreateObject(mode->algo));
      if (!mode->sm)
	return -1;
    }
  catch (...)
    {
      return -1;
    }

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = mode->sm->MinKeyLength();
  if (keylen)
    {
      CryptoPP::SecByteBlock key(keylen);
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      ivlen = mode->sm->DefaultIVLength();
      if (ivlen && !no_iv)
	{
	  mode->sm->SetKeyWithIV(key, key.size(), default_iv, ivlen);
	}
      else
	{
	  mode->sm->SetKey(key, key.size());
	}
    }

  return 0;
}

static int
bench_encrypt_cipher_mode_init (struct bench_obj *obj)
{
  return bench_crypt_symmetric_cipher_init<CryptoPP::ENCRYPTION>(obj);
}

static int
bench_decrypt_cipher_mode_init (struct bench_obj *obj)
{
  return bench_crypt_symmetric_cipher_init<CryptoPP::DECRYPTION>(obj);
}

static int
bench_encrypt_cipher_mode_no_iv_init (struct bench_obj *obj)
{
  return bench_crypt_symmetric_cipher_init<CryptoPP::ENCRYPTION, 1>(obj);
}

static int
bench_decrypt_cipher_mode_no_iv_init (struct bench_obj *obj)
{
  return bench_crypt_symmetric_cipher_init<CryptoPP::DECRYPTION, 1>(obj);
}

static void
bench_crypt_cipher_mode_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  delete mode->sm.release();
}

static void
bench_crypt_cipher_mode_do_bench (struct bench_obj *obj, void *buf,
				  size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  mode->sm->ProcessString(reinterpret_cast<uint8_t *>(buf), buflen);
}

static struct bench_ops cipher_mode_encrypt_no_iv_ops = {
  &bench_encrypt_cipher_mode_no_iv_init,
  &bench_crypt_cipher_mode_free,
  &bench_crypt_cipher_mode_do_bench
};

static struct bench_ops cipher_mode_decrypt_no_iv_ops = {
  &bench_decrypt_cipher_mode_no_iv_init,
  &bench_crypt_cipher_mode_free,
  &bench_crypt_cipher_mode_do_bench
};

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


template <int instance>
static int
bench_crypt_aead_mode_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  int keylen;
  int ivlen;

  try
    {
      mode->am = std::unique_ptr<CryptoPP::AuthenticatedSymmetricCipher>(
	CryptoPP::ObjectFactoryRegistry<CryptoPP::AuthenticatedSymmetricCipher, instance>::
	  Registry().CreateObject(mode->algo));
      if (!mode->am)
	return -1;
    }
  catch (...)
    {
      return -1;
    }

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = mode->am->MinKeyLength();
  if (keylen)
    {
      CryptoPP::SecByteBlock key(keylen);
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      ivlen = mode->am->DefaultIVLength();
      if (ivlen)
	{
	  mode->am->SetKeyWithIV(key, key.size(), default_iv, ivlen);
	}
      else
	{
	  mode->am->SetKey(key, key.size());
	}
    }

  return 0;
}

static int
bench_encrypt_aead_mode_init (struct bench_obj *obj)
{
  return bench_crypt_aead_mode_init<CryptoPP::ENCRYPTION>(obj);
}

static int
bench_decrypt_aead_mode_init (struct bench_obj *obj)
{
  return bench_crypt_aead_mode_init<CryptoPP::DECRYPTION>(obj);
}

static void
bench_crypt_aead_mode_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);

  delete mode->am.release();
}

static void
bench_crypt_aead_mode_do_bench (struct bench_obj *obj, void *buf,
				size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t tag[32];

  mode->am->Resynchronize(default_iv, mode->am->MinIVLength());
  mode->am->ProcessString(reinterpret_cast<uint8_t *>(buf), buflen);
  mode->am->TruncatedFinal(tag, mode->am->DigestSize());
  mode->am->Restart();
}

static void
bench_authenticate_aead_mode_do_bench (struct bench_obj *obj, void *buf,
				       size_t buflen)
{
  struct bench_cipher_mode *mode =
      reinterpret_cast<struct bench_cipher_mode *>(obj->priv);
  uint8_t tag[32];

  mode->am->Resynchronize(default_iv, mode->am->MinIVLength());
  mode->am->Update(reinterpret_cast<uint8_t *>(buf), buflen);
  mode->am->TruncatedFinal(tag, mode->am->DigestSize());
  mode->am->Restart();
}

static struct bench_ops aead_mode_encrypt_ops = {
  &bench_encrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_crypt_aead_mode_do_bench
};

static struct bench_ops aead_mode_decrypt_ops = {
  &bench_decrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_crypt_aead_mode_do_bench
};

static struct bench_ops aead_mode_authenticate_ops = {
  &bench_encrypt_aead_mode_init,
  &bench_crypt_aead_mode_free,
  &bench_authenticate_aead_mode_do_bench
};

static const struct bench_cipher_mode block_cipher_modes[] = {
  {"ECB enc", &cipher_mode_encrypt_no_iv_ops, "ECB"},
  {"ECB dec", &cipher_mode_decrypt_no_iv_ops, "ECB"},
  {"CBC enc", &cipher_mode_encrypt_ops, "CBC"},
  {"CBC dec", &cipher_mode_decrypt_ops, "CBC"},
  {"CFB enc", &cipher_mode_encrypt_ops, "CFB"},
  {"CFB dec", &cipher_mode_decrypt_ops, "CFB"},
  {"OFB enc", &cipher_mode_encrypt_ops, "OFB"},
  {"OFB dec", &cipher_mode_decrypt_ops, "OFB"},
  {"CTR enc", &cipher_mode_encrypt_ops, "CTR"},
  {"CTR dec", &cipher_mode_decrypt_ops, "CTR"},
  {"XTS enc", &cipher_mode_encrypt_ops, "XTS"},
  {"XTS dec", &cipher_mode_decrypt_ops, "XTS"},
  {"GCM enc", &aead_mode_encrypt_ops, "GCM"},
  {"GCM dec", &aead_mode_decrypt_ops, "GCM"},
  {"GCM auth", &aead_mode_authenticate_ops, "GCM"},
  {"EAX enc", &aead_mode_encrypt_ops, "EAX"},
  {"EAX dec", &aead_mode_decrypt_ops, "EAX"},
  {"EAX auth", &aead_mode_authenticate_ops, "EAX"},
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
  mode.ops = &cipher_mode_encrypt_ops;
  cipher_bench_one (algo, &mode, 1);
#ifdef HAVE_CHACHAPOLY
  if (strcmp(algo, "ChaCha") == 0)
    {
      mode.name = "POLY1305 enc";
      mode.ops = &aead_mode_encrypt_ops;
      cipher_bench_one ("ChaCha20/Poly1305", &mode, 1);
      mode.name = "POLY1305 dec";
      mode.ops = &aead_mode_decrypt_ops;
      cipher_bench_one ("ChaCha20/Poly1305", &mode, 1);
      mode.name = "POLY1305 auth";
      mode.ops = &aead_mode_authenticate_ops;
      cipher_bench_one ("ChaCha20/Poly1305", &mode, 1);
    }
#endif

  if (cipher_header_printed)
    bench_print_footer (14);
}

static void
_cipher_bench (std::tuple<std::string, enum bench_cipher_type> &algo)
{
  struct bench_cipher_mode mode = {};

  switch (std::get<1>(algo))
    {
    case BENCH_CIPHER_TYPE_BLOCK_CIPHER:
      _block_cipher_bench(std::get<0>(algo).c_str());
      break;

    case BENCH_CIPHER_TYPE_STREAM_CIPHER:
      _stream_cipher_bench(std::get<0>(algo).c_str());
      break;
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
	{
	  for (std::tuple<std::string, enum bench_cipher_type> algo: cipher_algos)
	    if (strcasecmp(std::get<0>(algo).c_str(), argv[i]) == 0)
	      _cipher_bench (algo);
	}
    }
  else
    {
      for (std::tuple<std::string, enum bench_cipher_type> algo: cipher_algos)
	_cipher_bench (algo);
    }
}

/*********************************************************** Hash benchmarks. */

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  const char *algo;
  std::unique_ptr<CryptoPP::HashTransformation> ht;
};

static void bench_register_hashes(void)
{
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::CRC32>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::CRC32C>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::Weak::MD5>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA1>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA256>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA512>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::RIPEMD160>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::Whirlpool>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA3_224>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA3_256>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA3_384>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SHA3_512>();
#ifdef HAVE_SM3
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::SM3>();
#endif
#ifdef HAVE_BLAKE2
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::BLAKE2s>();
  CryptoPP::RegisterDefaultFactoryFor<CryptoPP::HashTransformation, CryptoPP::BLAKE2b>();
#endif
}

static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);
  int ret = 0;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  try
    {
      mode->ht = std::unique_ptr<CryptoPP::HashTransformation>(
	CryptoPP::ObjectFactoryRegistry<CryptoPP::HashTransformation>::
	  Registry().CreateObject(mode->algo));
      if (!mode->ht)
	ret = -1;
    }
  catch (...)
    {
      ret = -1;
    }

  if (ret < 0)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n", mode->algo);
      exit (1);
    }

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);

  delete mode->ht.release();
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_hash_mode *mode =
    reinterpret_cast<struct bench_hash_mode *>(obj->priv);
  uint8_t digest[512];

  mode->ht->Update(reinterpret_cast<uint8_t *>(buf), buflen);
  mode->ht->Final(digest);
  mode->ht->Restart();
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
  std::vector<std::string> hash_algos =
    CryptoPP::ObjectFactoryRegistry<CryptoPP::HashTransformation>::
      Registry().GetFactoryNames();
  int i;

  bench_print_section ("hash", "Hash");
  bench_print_header (14, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  for (std::string algo: hash_algos)
	    if (strcasecmp(algo.c_str(), argv[i]) == 0)
	      _hash_bench (algo.c_str());
	}
    }
  else
    {
      for (std::string algo: hash_algos)
	_hash_bench (algo.c_str());
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
  int version;

#if CRYPTOPP_VERSION >= 570
  version = CryptoPP::LibraryVersion();
#else
  version = CRYPTOPP_VERSION;
#endif

  printf("%s: Crypto++ %d.%d.%d\n",
	 PGM, version / 100, (version / 10) % 10, version % 10);

  bench_register_hashes();
  bench_register_ciphers();

  return slope_main_template(argc, argv, groups, PGM, LIBNAME);
}

#endif /* HAVE_CRYPTOPP */
