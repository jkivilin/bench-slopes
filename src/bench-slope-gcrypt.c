/* bench-slope-gcrypt.c - for libgcrypt
 * Copyright (C) 2013,2017-2023 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#if defined(HAVE_CONFIG_H) && !defined(HAVE_LIBGCRYPT_1_6)

int main(void)
{
  fprintf(stderr, "Missing libgcrypt\n");
  return 0;
}

#else /* HAVE_LIBGCRYPT_1_6 */

#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>

#include "slope.h"

#include <gcrypt.h>

#ifndef STR
#define STR(v) #v
#define STR2(v) STR(v)
#endif

#define LIBNAME "libgcrypt"
#define PGM "bench-slope-gcrypt"


/********************************************************* Cipher benchmarks. */

struct bench_cipher_mode
{
  int mode;
  const char *name;
  struct bench_ops *ops;

  int algo;
  gcry_cipher_hd_t hd;
};


static int
bench_encrypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd;
  int err, keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  err = gcry_cipher_open (&hd, mode->algo, mode->mode, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      exit (1);
    }

  keylen = gcry_cipher_get_algo_keylen (mode->algo);
#ifdef HAVE_LIBGCRYPT_1_10
  keylen *= (mode->mode == GCRY_CIPHER_MODE_SIV) + 1;
#endif

  if (keylen)
    {
      char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      err = gcry_cipher_setkey (hd, key, keylen);
      if (err)
	{
	  fprintf (stderr, PGM ": gcry_cipher_setkey failed: %s\n",
		   gpg_strerror (err));
	  gcry_cipher_close (hd);
	  exit (1);
	}
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      gcry_cipher_close (hd);
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static void
bench_encrypt_free (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;

  gcry_cipher_close (hd);
}

static void
bench_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;

  err = gcry_cipher_reset (hd);
  if (!err)
    err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;

  err = gcry_cipher_reset (hd);
  if (!err)
    err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static struct bench_ops encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_encrypt_do_bench
};

static struct bench_ops decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_decrypt_do_bench
};


#ifdef HAVE_LIBGCRYPT_1_8
static int
bench_xts_encrypt_init (struct bench_obj *obj)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd;
  int err, keylen;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  err = gcry_cipher_open (&hd, mode->algo, mode->mode, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error opening cipher `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      exit (1);
    }

  /* Double key-length for XTS. */
  keylen = gcry_cipher_get_algo_keylen (mode->algo) * 2;
  if (keylen)
    {
      char key[keylen];
      int i;

      for (i = 0; i < keylen; i++)
	key[i] = 0x33 ^ (11 - i);

      err = gcry_cipher_setkey (hd, key, keylen);
      if (err)
	{
	  fprintf (stderr, PGM ": gcry_cipher_setkey failed: %s\n",
		   gpg_strerror (err));
	  gcry_cipher_close (hd);
	  exit (1);
	}
    }
  else
    {
      fprintf (stderr, PGM ": failed to get key length for algorithm `%s'\n",
	       gcry_cipher_algo_name (mode->algo));
      gcry_cipher_close (hd);
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static struct bench_ops xts_encrypt_ops = {
  &bench_xts_encrypt_init,
  &bench_encrypt_free,
  &bench_encrypt_do_bench
};

static struct bench_ops xts_decrypt_ops = {
  &bench_xts_encrypt_init,
  &bench_encrypt_free,
  &bench_decrypt_do_bench
};
#endif /* HAVE_LIBGCRYPT_1_8 */


static void
bench_ccm_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[8];
  char nonce[11] = { 0x80, 0x01, };
  uint64_t params[3];

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = buflen;
  params[1] = 0;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_ccm_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[8] = { 0, };
  char nonce[11] = { 0x80, 0x01, };
  uint64_t params[3];

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = buflen;
  params[1] = 0;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_checktag (hd, tag, sizeof (tag));
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_NO_ERROR);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_ccm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[8] = { 0, };
  char nonce[11] = { 0x80, 0x01, };
  uint64_t params[3];
  char data = 0xff;

  gcry_cipher_setiv (hd, nonce, sizeof (nonce));

  /* Set CCM lengths */
  params[0] = sizeof (data);	/*datalen */
  params[1] = buflen;		/*aadlen */
  params[2] = sizeof (tag);
  err =
    gcry_cipher_ctl (hd, GCRYCTL_SET_CCM_LENGTHS, params, sizeof (params));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_ctl failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_authenticate (hd, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_authenticate failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_encrypt (hd, &data, sizeof (data), &data, sizeof (data));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
	       gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static struct bench_ops ccm_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_encrypt_do_bench
};

static struct bench_ops ccm_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_decrypt_do_bench
};

static struct bench_ops ccm_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ccm_authenticate_do_bench
};


static void
bench_aead_encrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen,
			     const char *nonce, size_t noncelen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[16];

  gcry_cipher_reset (hd);
  gcry_cipher_setiv (hd, nonce, noncelen);

  gcry_cipher_final (hd);
  err = gcry_cipher_encrypt (hd, buf, buflen, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_aead_decrypt_do_bench (struct bench_obj *obj, void *buf, size_t buflen,
			     const char *nonce, size_t noncelen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[16] = { 0, };

  gcry_cipher_reset (hd);
  gcry_cipher_set_decryption_tag (hd, tag, 16);

  gcry_cipher_setiv (hd, nonce, noncelen);

  gcry_cipher_final (hd);
  err = gcry_cipher_decrypt (hd, buf, buflen, buf, buflen);
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_NO_ERROR);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_decrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_checktag (hd, tag, sizeof (tag));
  if (gpg_err_code (err) == GPG_ERR_CHECKSUM)
    err = gpg_error (GPG_ERR_NO_ERROR);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}

static void
bench_aead_authenticate_do_bench (struct bench_obj *obj, void *buf,
				  size_t buflen, const char *nonce,
				  size_t noncelen)
{
  struct bench_cipher_mode *mode = obj->priv;
  gcry_cipher_hd_t hd = mode->hd;
  int err;
  char tag[16] = { 0, };
  char data = 0xff;

  gcry_cipher_reset (hd);

  if (noncelen > 0)
    {
      err = gcry_cipher_setiv (hd, nonce, noncelen);
      if (err)
	{
	  fprintf (stderr, PGM ": gcry_cipher_setiv failed: %s\n",
	       gpg_strerror (err));
	  gcry_cipher_close (hd);
	  exit (1);
	}
    }

  err = gcry_cipher_authenticate (hd, buf, buflen);
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_authenticate failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  gcry_cipher_final (hd);
  err = gcry_cipher_encrypt (hd, &data, sizeof (data), &data, sizeof (data));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_encrypt failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }

  err = gcry_cipher_gettag (hd, tag, sizeof (tag));
  if (err)
    {
      fprintf (stderr, PGM ": gcry_cipher_gettag failed: %s\n",
           gpg_strerror (err));
      gcry_cipher_close (hd);
      exit (1);
    }
}


static void
bench_gcm_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops gcm_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_encrypt_do_bench
};

static struct bench_ops gcm_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_decrypt_do_bench
};

static struct bench_ops gcm_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_authenticate_do_bench
};


static void
bench_ocb_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[15] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_ocb_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[15] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_ocb_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  char nonce[15] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops ocb_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ocb_encrypt_do_bench
};

static struct bench_ops ocb_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ocb_decrypt_do_bench
};


#ifdef HAVE_LIBGCRYPT_1_10
static struct bench_ops ocb_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_ocb_authenticate_do_bench
};
static void
bench_siv_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  bench_aead_encrypt_do_bench (obj, buf, buflen, NULL, 0);
}

static void
bench_siv_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  bench_aead_decrypt_do_bench (obj, buf, buflen, NULL, 0);
}

static void
bench_siv_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  bench_aead_authenticate_do_bench (obj, buf, buflen, NULL, 0);
}

static struct bench_ops siv_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_siv_encrypt_do_bench
};

static struct bench_ops siv_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_siv_decrypt_do_bench
};

static struct bench_ops siv_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_siv_authenticate_do_bench
};


static void
bench_gcm_siv_encrypt_do_bench (struct bench_obj *obj, void *buf,
				size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_siv_decrypt_do_bench (struct bench_obj *obj, void *buf,
				size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_gcm_siv_authenticate_do_bench (struct bench_obj *obj, void *buf,
				     size_t buflen)
{
  char nonce[12] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops gcm_siv_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_siv_encrypt_do_bench
};

static struct bench_ops gcm_siv_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_siv_decrypt_do_bench
};

static struct bench_ops gcm_siv_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_gcm_siv_authenticate_do_bench
};
#endif /* HAVE_LIBGCRYPT_1_10 */


#ifdef HAVE_LIBGCRYPT_1_9
static void
bench_eax_encrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01, 0x00 };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_eax_decrypt_do_bench (struct bench_obj *obj, void *buf,
			    size_t buflen)
{
  char nonce[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01, 0x00 };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_eax_authenticate_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  char nonce[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                     0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
                     0x00, 0x00, 0x01, 0x00 };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops eax_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_eax_encrypt_do_bench
};

static struct bench_ops eax_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_eax_decrypt_do_bench
};

static struct bench_ops eax_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_eax_authenticate_do_bench
};
#endif /* HAVE_LIBGCRYPT_1_9 */


static void
bench_poly1305_encrypt_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  char nonce[8] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad };
  bench_aead_encrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_poly1305_decrypt_do_bench (struct bench_obj *obj, void *buf,
				 size_t buflen)
{
  char nonce[8] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad };
  bench_aead_decrypt_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static void
bench_poly1305_authenticate_do_bench (struct bench_obj *obj, void *buf,
				      size_t buflen)
{
  char nonce[8] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad };
  bench_aead_authenticate_do_bench (obj, buf, buflen, nonce, sizeof(nonce));
}

static struct bench_ops poly1305_encrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_poly1305_encrypt_do_bench
};

static struct bench_ops poly1305_decrypt_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_poly1305_decrypt_do_bench
};

static struct bench_ops poly1305_authenticate_ops = {
  &bench_encrypt_init,
  &bench_encrypt_free,
  &bench_poly1305_authenticate_do_bench
};


static struct bench_cipher_mode cipher_modes[] = {
  {GCRY_CIPHER_MODE_ECB, "ECB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_ECB, "ECB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CBC, "CBC enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CBC, "CBC dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CFB, "CFB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CFB, "CFB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_OFB, "OFB enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_OFB, "OFB dec", &decrypt_ops},
  {GCRY_CIPHER_MODE_CTR, "CTR enc", &encrypt_ops},
  {GCRY_CIPHER_MODE_CTR, "CTR dec", &decrypt_ops},
#ifdef HAVE_LIBGCRYPT_1_8
  {GCRY_CIPHER_MODE_XTS, "XTS enc", &xts_encrypt_ops},
  {GCRY_CIPHER_MODE_XTS, "XTS dec", &xts_decrypt_ops},
#endif
  {GCRY_CIPHER_MODE_CCM, "CCM enc", &ccm_encrypt_ops},
  {GCRY_CIPHER_MODE_CCM, "CCM dec", &ccm_decrypt_ops},
  {GCRY_CIPHER_MODE_CCM, "CCM auth", &ccm_authenticate_ops},
#ifdef HAVE_LIBGCRYPT_1_9
  {GCRY_CIPHER_MODE_EAX, "EAX enc", &eax_encrypt_ops},
  {GCRY_CIPHER_MODE_EAX, "EAX dec", &eax_decrypt_ops},
  {GCRY_CIPHER_MODE_EAX, "EAX auth", &eax_authenticate_ops},
#endif
  {GCRY_CIPHER_MODE_GCM, "GCM enc", &gcm_encrypt_ops},
  {GCRY_CIPHER_MODE_GCM, "GCM dec", &gcm_decrypt_ops},
  {GCRY_CIPHER_MODE_GCM, "GCM auth", &gcm_authenticate_ops},
  {GCRY_CIPHER_MODE_OCB, "OCB enc",  &ocb_encrypt_ops},
  {GCRY_CIPHER_MODE_OCB, "OCB dec",  &ocb_decrypt_ops},
  {GCRY_CIPHER_MODE_OCB, "OCB auth", &ocb_authenticate_ops},
#ifdef HAVE_LIBGCRYPT_1_10
  {GCRY_CIPHER_MODE_SIV, "SIV enc", &siv_encrypt_ops},
  {GCRY_CIPHER_MODE_SIV, "SIV dec", &siv_decrypt_ops},
  {GCRY_CIPHER_MODE_SIV, "SIV auth", &siv_authenticate_ops},
  {GCRY_CIPHER_MODE_GCM_SIV, "GCM-SIV enc", &gcm_siv_encrypt_ops},
  {GCRY_CIPHER_MODE_GCM_SIV, "GCM-SIV dec", &gcm_siv_decrypt_ops},
  {GCRY_CIPHER_MODE_GCM_SIV, "GCM-SIV auth", &gcm_siv_authenticate_ops},
#endif
  {GCRY_CIPHER_MODE_POLY1305, "POLY1305 enc", &poly1305_encrypt_ops},
  {GCRY_CIPHER_MODE_POLY1305, "POLY1305 dec", &poly1305_decrypt_ops},
  {GCRY_CIPHER_MODE_POLY1305, "POLY1305 auth", &poly1305_authenticate_ops},
  {0},
};


static void
cipher_bench_one (int algo, struct bench_cipher_mode *pmode)
{
  struct bench_cipher_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;
  unsigned int blklen;
  unsigned int keylen;

  mode.algo = algo;

  /* Check if this mode is ok */
  blklen = gcry_cipher_get_algo_blklen (algo);
  if (!blklen)
    return;

  keylen = gcry_cipher_get_algo_keylen (algo);
  if (!keylen)
    return;

  /* Stream cipher? Only test with "ECB" and POLY1305. */
  if (blklen == 1 && (mode.mode != GCRY_CIPHER_MODE_ECB &&
		      mode.mode != GCRY_CIPHER_MODE_POLY1305))
    return;
  if (blklen == 1 && mode.mode == GCRY_CIPHER_MODE_ECB)
    {
      mode.mode = GCRY_CIPHER_MODE_STREAM;
      mode.name = mode.ops == &encrypt_ops ? "STREAM enc" : "STREAM dec";
    }

  /* Poly1305 has restriction for cipher algorithm */
  if (mode.mode == GCRY_CIPHER_MODE_POLY1305 && algo != GCRY_CIPHER_CHACHA20)
    return;

  /* CCM has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_CCM && blklen != GCRY_CCM_BLOCK_LEN)
    return;

  /* GCM has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_GCM && blklen != GCRY_GCM_BLOCK_LEN)
    return;

#ifdef HAVE_LIBGCRYPT_1_8
  /* XTS has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_XTS && blklen != GCRY_XTS_BLOCK_LEN)
    return;
#endif

#ifdef HAVE_LIBGCRYPT_1_10
  /* SIV has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_SIV && blklen != GCRY_SIV_BLOCK_LEN)
    return;

  /* GCM-SIV has restrictions for block-size */
  if (mode.mode == GCRY_CIPHER_MODE_GCM_SIV && blklen != GCRY_SIV_BLOCK_LEN)
    return;

  /* GCM-SIV has restrictions for key length */
  if (mode.mode == GCRY_CIPHER_MODE_GCM_SIV && !(keylen == 16 || keylen == 32))
    return;
#else
  (void)keylen;
#endif

  /* Our OCB implementaion has restrictions for block-size.  */
  if (mode.mode == GCRY_CIPHER_MODE_OCB && blklen != GCRY_OCB_BLOCK_LEN)
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

  algoname = gcry_cipher_algo_name (algo);

  bench_print_header (14, algoname);

  for (i = 0; cipher_modes[i].mode; i++)
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
          algo = gcry_cipher_map_name (argv[i]);
          if (algo)
            _cipher_bench (algo);
        }
    }
  else
    {
      for (i = 1; i < 400; i++)
        if (!gcry_cipher_test_algo (i))
          _cipher_bench (i);
    }
}


/*********************************************************** Hash benchmarks. */

struct bench_hash_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
  gcry_md_hd_t hd;
};


static int
bench_hash_init (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  gcry_md_hd_t hd;
  int err;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  err = gcry_md_open (&hd, mode->algo, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error opening hash `%s'\n",
	       gcry_md_algo_name (mode->algo));
      exit (1);
    }

  mode->hd = hd;

  return 0;
}

static void
bench_hash_free (struct bench_obj *obj)
{
  struct bench_hash_mode *mode = obj->priv;
  gcry_md_hd_t hd = mode->hd;

  gcry_md_close (hd);
}

static void
bench_hash_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_hash_mode *mode = obj->priv;
  gcry_md_hd_t hd = mode->hd;

  gcry_md_reset (hd);
  gcry_md_write (hd, buf, buflen);
  gcry_md_final (hd);
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
    bench_print_algo (-14, gcry_md_algo_name (algo));
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
	  algo = gcry_md_map_name (argv[i]);
	  if (algo)
	    _hash_bench (algo);
	}
    }
  else
    {
      for (i = 1; i < 400; i++)
	if (!gcry_md_test_algo (i))
	  _hash_bench (i);
    }

  bench_print_footer (14);
}


/************************************************************ MAC benchmarks. */

struct bench_mac_mode
{
  const char *name;
  struct bench_ops *ops;

  int algo;
  gcry_mac_hd_t hd;
};


static int
bench_mac_init (struct bench_obj *obj)
{
  struct bench_mac_mode *mode = obj->priv;
  gcry_mac_hd_t hd;
  int err;
  unsigned int keylen;
  void *key;

  obj->min_bufsize = BUF_START_SIZE;
  obj->max_bufsize = BUF_END_SIZE;
  obj->step_size = BUF_STEP_SIZE;

  keylen = gcry_mac_get_algo_keylen (mode->algo);
  if (keylen == 0)
    keylen = 32;
  key = malloc (keylen);
  if (!key)
    {
      fprintf (stderr, PGM ": couldn't allocate %d bytes\n", keylen);
      exit (1);
    }
  memset(key, 42, keylen);

  err = gcry_mac_open (&hd, mode->algo, 0, NULL);
  if (err)
    {
      fprintf (stderr, PGM ": error opening mac `%s'\n",
	       gcry_mac_algo_name (mode->algo));
      free (key);
      exit (1);
    }

  err = gcry_mac_setkey (hd, key, keylen);
  if (err)
    {
      fprintf (stderr, PGM ": error setting key for mac `%s'\n",
	       gcry_mac_algo_name (mode->algo));
      free (key);
      exit (1);
    }

  switch (mode->algo)
    {
    default:
      break;
    case GCRY_MAC_POLY1305_AES:
    case GCRY_MAC_POLY1305_CAMELLIA:
    case GCRY_MAC_POLY1305_TWOFISH:
    case GCRY_MAC_POLY1305_SERPENT:
    case GCRY_MAC_POLY1305_SEED:
      gcry_mac_setiv (hd, key, 16);
      break;
    }

  mode->hd = hd;

  free (key);
  return 0;
}

static void
bench_mac_free (struct bench_obj *obj)
{
  struct bench_mac_mode *mode = obj->priv;
  gcry_mac_hd_t hd = mode->hd;

  gcry_mac_close (hd);
}

static void
bench_mac_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_mac_mode *mode = obj->priv;
  gcry_mac_hd_t hd = mode->hd;
  size_t bs;
  char b;

  gcry_mac_reset (hd);
  gcry_mac_write (hd, buf, buflen);
  bs = sizeof(b);
  gcry_mac_read (hd, &b, &bs);
}

static struct bench_ops mac_ops = {
  &bench_mac_init,
  &bench_mac_free,
  &bench_mac_do_bench
};


static struct bench_mac_mode mac_modes[] = {
  {"", &mac_ops},
  {0},
};


static void
mac_bench_one (int algo, struct bench_mac_mode *pmode)
{
  struct bench_mac_mode mode = *pmode;
  struct bench_obj obj = { 0 };
  double result;

  mode.algo = algo;

  if (mode.name[0] == '\0')
    bench_print_algo (-18, gcry_mac_algo_name (algo));
  else
    bench_print_algo (18, mode.name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  result = do_slope_benchmark (&obj);

  bench_print_result (result);
}

static void
_mac_bench (int algo)
{
  int i;

  for (i = 0; mac_modes[i].name; i++)
    mac_bench_one (algo, &mac_modes[i]);
}

void
mac_bench (char **argv, int argc)
{
  int i, algo;

  bench_print_section ("mac", "MAC");
  bench_print_header (18, "");

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  algo = gcry_mac_map_name (argv[i]);
	  if (algo)
	    _mac_bench (algo);
	}
    }
  else
    {
      for (i = 1; i < 600; i++)
	if (!gcry_mac_test_algo (i))
	  _mac_bench (i);
    }

  bench_print_footer (18);
}


/************************************************************ KDF benchmarks. */

struct bench_kdf_mode
{
  struct bench_ops *ops;

  int algo;
  int subalgo;
};


static int
bench_kdf_init (struct bench_obj *obj)
{
  struct bench_kdf_mode *mode = obj->priv;

  if (mode->algo == GCRY_KDF_PBKDF2)
    {
      obj->min_bufsize = 2;
      obj->max_bufsize = 2 * 32;
      obj->step_size = 2;
    }

  return 0;
}

static void
bench_kdf_free (struct bench_obj *obj)
{
  (void)obj;
}

static void
bench_kdf_do_bench (struct bench_obj *obj, void *buf, size_t buflen)
{
  struct bench_kdf_mode *mode = obj->priv;
  char keybuf[16];

  (void)buf;

  if (mode->algo == GCRY_KDF_PBKDF2)
    {
      gcry_kdf_derive("qwerty", 6, mode->algo, mode->subalgo, "01234567", 8,
		      buflen, sizeof(keybuf), keybuf);
    }
}

static struct bench_ops kdf_ops = {
  &bench_kdf_init,
  &bench_kdf_free,
  &bench_kdf_do_bench
};


static void
kdf_bench_one (int algo, int subalgo)
{
  struct bench_kdf_mode mode = { &kdf_ops };
  struct bench_obj obj = { 0 };
  double nsecs_per_iteration;
  double cycles_per_iteration;
  char algo_name[32];
  char nsecpiter_buf[16];
  char cpiter_buf[16];
  char mhz_buf[16];

  mode.algo = algo;
  mode.subalgo = subalgo;

  switch (subalgo)
    {
    case GCRY_MD_CRC32:
    case GCRY_MD_CRC32_RFC1510:
    case GCRY_MD_CRC24_RFC2440:
    case GCRY_MD_MD4:
      /* Skip CRC32s. */
      return;
    }

  if (gcry_md_get_algo_dlen (subalgo) == 0)
    {
      /* Skip XOFs */
      return;
    }

  *algo_name = 0;

  if (algo == GCRY_KDF_PBKDF2)
    {
      snprintf (algo_name, sizeof(algo_name), "PBKDF2-HMAC-%s",
		gcry_md_algo_name (subalgo));
    }

  bench_print_algo (-24, algo_name);

  obj.ops = mode.ops;
  obj.priv = &mode;

  nsecs_per_iteration = do_slope_benchmark (&obj);

  strcpy(cpiter_buf, settings.csv_mode ? "" : "-");

  double_to_str (nsecpiter_buf, sizeof (nsecpiter_buf), nsecs_per_iteration);

  /* If user didn't provide CPU speed, we cannot show cycles/iter results.  */
  if (settings.bench_ghz > 0.0)
    {
      cycles_per_iteration = nsecs_per_iteration * settings.bench_ghz;
      double_to_str (cpiter_buf, sizeof (cpiter_buf), cycles_per_iteration);
      double_to_str (mhz_buf, sizeof (mhz_buf), settings.bench_ghz * 1000);
    }

  if (settings.csv_mode)
    {
      if (settings.auto_ghz)
        printf ("%s,%s,%s,,,,,,,,,%s,ns/iter,%s,c/iter,%s,Mhz\n",
                settings.current_section_name,
                settings.current_algo_name ? settings.current_algo_name : "",
                settings.current_mode_name ? settings.current_mode_name : "",
                nsecpiter_buf,
                cpiter_buf,
                mhz_buf);
      else
        printf ("%s,%s,%s,,,,,,,,,%s,ns/iter,%s,c/iter\n",
                settings.current_section_name,
                settings.current_algo_name ? settings.current_algo_name : "",
                settings.current_mode_name ? settings.current_mode_name : "",
                nsecpiter_buf,
                cpiter_buf);
    }
  else
    {
      if (settings.auto_ghz)
        printf ("%14s %13s %9s\n", nsecpiter_buf, cpiter_buf, mhz_buf);
      else
        printf ("%14s %13s\n", nsecpiter_buf, cpiter_buf);
    }
}

void
kdf_bench (char **argv, int argc)
{
  char algo_name[32];
  int i, j;

  if (settings.raw_mode)
    return;

  bench_print_section ("kdf", "KDF");

  if (!settings.csv_mode)
    {
      printf (" %-*s | ", 24, "");
      if (settings.auto_ghz)
        printf ("%14s %13s %9s\n", "nanosecs/iter", "cycles/iter", "auto Mhz");
      else
        printf ("%14s %13s\n", "nanosecs/iter", "cycles/iter");
    }

  if (argv && argc)
    {
      for (i = 0; i < argc; i++)
	{
	  for (j = 1; j < 400; j++)
	    {
	      if (gcry_md_test_algo (j))
		continue;

	      snprintf (algo_name, sizeof(algo_name), "PBKDF2-HMAC-%s",
			gcry_md_algo_name (j));

	      if (!strcmp(argv[i], algo_name))
		kdf_bench_one (GCRY_KDF_PBKDF2, j);
	    }
	}
    }
  else
    {
      for (i = 1; i < 400; i++)
	if (!gcry_md_test_algo (i))
	  kdf_bench_one (GCRY_KDF_PBKDF2, i);
    }

  bench_print_footer (24);
}


/************************************************************** Main program. */


int
main (int argc, char **argv)
{
  static const struct bench_group groups[] =
    {
      { "hash", hash_bench },
      { "mac", mac_bench },
      { "cipher", cipher_bench },
      { "kdf", kdf_bench },
      { NULL, NULL }
    };

  printf("%s: libgcrypt: %s\n", PGM, gcry_check_version (NULL));

  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr, PGM ": version mismatch; pgm=%s, library=%s\n",
	       GCRYPT_VERSION, gcry_check_version (NULL));
      exit (1);
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);

  return slope_main_template(argc, argv, groups, PGM, LIBNAME);
}

#endif /* HAVE_LIBGCRYPT_1_6 */
