#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "crypto.h"

static const char HEX_MAP[] = {'0','1','2','3','4','5','6','7','8','9',
			       'A','B','C','D','E','F'};
struct _crypto_sym_trans_t
{
  EVP_CIPHER_CTX c_ctx;
  HMAC_CTX h_ctx;
  unsigned char key[32], iv[32];
  unsigned char buffer[96];
  int initialized, finalized;
  size_t buffer_len;
};

struct _crypto_sym_t
{
  unsigned char key[32];
};

volatile void
crypto_secure_erase (volatile void *dst, size_t len)
{
  volatile unsigned char *chars;
  size_t i;

  /* Iterate over each char zeroing memory */
  chars = (volatile unsigned char *)dst;
  for (i = 0; i < len; i++)
    chars[i] = 0;
}

void
crypto_sym_genkey (unsigned char * key, size_t len)
{
  RAND_bytes (key, len);
}

unsigned char *
crypto_bytes_to_hex (const unsigned char * bytes, size_t len)
{
  size_t i, out_len;
  unsigned char * out;

  /* Initialize Output String */
  out_len = (len << 1) + 1;
  out = (unsigned char *) malloc (out_len * sizeof (char));

  /* Iterate over each byte converting it */
  for (i = 0; i < len; i++)
    {
      out[(i<<1) + 1] = HEX_MAP[bytes[i] & 0xF];
      out[(i<<1)] = HEX_MAP[(bytes[i] >> 4) & 0xF];
    }
  out[out_len-1] = 0;
  return out;
}

unsigned char *
crypto_hex_to_bytes (const unsigned char * hex, size_t * olen)
{
  size_t in_len, out_len, i;
  unsigned char * out, tmp;

  /* Check input length */
  in_len = strlen (hex);
  out_len = in_len >> 1;
  if (in_len != out_len << 1)
    return NULL;

  /* Create the Output Byte String */
  out = (unsigned char *) malloc (out_len * sizeof (char));

  /* Iterate over each grouping of bytes, coverting them down */
  for (i = 0; i < out_len; i++)
    {
      tmp = hex[i<<1];
      if (tmp >= '0' && tmp <= '9')
	tmp -= '0';
      else if (tmp >= 'A' && tmp <= 'F')
	tmp -= 'A' + 10;
      else if (tmp >= 'a' && tmp <= 'f')
	tmp -= 'a' + 10;
      out[i] = tmp << 4;
      tmp = hex[(i<<1) + 1];
      if (tmp >= '0' && tmp <= '9')
	tmp -= '0';
      else if (tmp >= 'A' && tmp <= 'F')
	tmp -= 'A' + 10;
      else if (tmp >= 'a' && tmp <= 'f')
	tmp -= 'a' + 10;
      out[i] |= tmp;
    }

  /* Return Length */
  if (olen != NULL)
    *olen = out_len;

  return out;
}

static unsigned char *
crypto_hash (const unsigned char * bytes, size_t len, size_t * olen,
	     const EVP_MD *algo)
{
  EVP_MD_CTX mdctx;
  int ret, iolen;
  unsigned char * out;

  /* Setup and run the hashing algo */
  EVP_MD_CTX_init (&mdctx);
  ret = EVP_DigestInit_ex (&mdctx, algo, NULL);
  if (ret != 1)
    return NULL;
  ret = EVP_DigestUpdate (&mdctx, bytes, len);
  if (ret != 1)
    return NULL;

  /* Allocate Hashed String */
  out = (unsigned char *) malloc (EVP_MD_size (algo));
  ret = EVP_DigestFinal_ex (&mdctx, out, &iolen);
  if (ret != 1)
    {
      free (out);
      return NULL;
    }
  
  *olen = iolen;
  return out;
}

unsigned char *
crypto_sha256 (const unsigned char * bytes, size_t len, size_t * olen)
{
  return crypto_hash (bytes, len, olen, EVP_sha256 ());
}

unsigned char *
crypto_sha512 (const unsigned char * bytes, size_t len, size_t * olen)
{
  return crypto_hash (bytes, len, olen, EVP_sha512 ());
}

enum crypto_status
crypto_sym_init (crypto_sym_t * crypto, const unsigned char * key, size_t len, int hash)
{
  int ret;
  unsigned char iv[32], keyc[32];

  /* Generate Keying Material */
  if (hash == 0)
    if (len == 32)
      memcpy (keyc, key, len);
    else
      return CRYPTO_INVALID_KEY;
  else
    {
      /* Hash the keying material */
      ret = EVP_BytesToKey (EVP_aes_256_cbc (), EVP_sha256(),
			    "B623uS&HB6m%6vQqQsAt&aK6PX@^qTkU",
			    key, len, 14,
			    keyc, iv);

      /* Make sure our key is long enough */
      if (ret != 32)
	return CRYPTO_INVALID_KEY;
    }

  /* Create Crypto Struct and secure memory */
  *crypto = (crypto_sym_t) malloc (sizeof (struct _crypto_sym_t));
  mlock (*crypto, sizeof (struct _crypto_sym_t));
  memcpy ((*crypto)->key, keyc, 32);
  return CRYPTO_SUCCESS;
}

void
crypto_sym_destroy (crypto_sym_t crypto)
{
  /* Securely erase and free cryptographic data */
  crypto_secure_erase (crypto, sizeof (struct _crypto_sym_t));
  munlock (crypto, sizeof (struct _crypto_sym_t));
  free (crypto);
}

enum crypto_status
crypto_sym_enc (crypto_sym_t crypto,
		unsigned char ** buffer, size_t * buffer_len,
		const unsigned char * data, size_t len)
{
  EVP_CIPHER_CTX ectx;
  HMAC_CTX hctx;
  unsigned char iv[32], hash[64];
  int ret;
  size_t block_size, pos;

  /* Initialize Contexts */
  EVP_CIPHER_CTX_init (&ectx);
  HMAC_CTX_init (&hctx);

  /* Generate Key Material */
  crypto_sym_genkey (iv, 32);

  /* Setup Contexts */
  ret = EVP_EncryptInit_ex (&ectx, EVP_aes_256_cbc(), NULL, crypto->key, iv);
  if (ret != 1)
    {
      EVP_CIPHER_CTX_cleanup (&ectx);
      HMAC_CTX_init (&hctx);
      return CRYPTO_UNKNOWN;
    }
  ret = HMAC_Init (&hctx, crypto->key, 32, EVP_sha512());
  if (ret != 1)
    {
      EVP_CIPHER_CTX_cleanup (&ectx);
      HMAC_CTX_init (&hctx);
      return CRYPTO_UNKNOWN;
    }

  /* Setup Data */
  block_size = EVP_CIPHER_CTX_block_size (&ectx);
  *buffer_len = crypto_sym_enc_size (len);
  if (*buffer != NULL)
    free (*buffer);
  *buffer = (unsigned char *) malloc (*buffer_len * sizeof (char));
  
  /* Write IV Data */
  memcpy (*buffer, iv, 32);
  pos = 32;
  HMAC_Update (&hctx, iv, 32);

  /* Encrypt and Write Data */
  HMAC_Update (&hctx, data, len);
  if (EVP_EncryptUpdate (&ectx, *buffer + pos, &ret, data, len) == 0)
    {
      EVP_CIPHER_CTX_cleanup (&ectx);
      HMAC_CTX_cleanup (&hctx);
      free (*buffer);
      return CRYPTO_UNKNOWN;
    }
  pos += ret;
  EVP_EncryptFinal_ex(&ectx, *buffer + pos, &ret);
  pos += ret;

  /* Write HMAC */
  block_size = 64;
  HMAC_Final (&hctx, *buffer + pos, &ret);
  pos += ret;

  /* Cleanup */
  EVP_CIPHER_CTX_cleanup (&ectx);
  HMAC_CTX_cleanup (&hctx);
  *buffer_len = pos;

  return CRYPTO_SUCCESS;
}

enum crypto_status
crypto_sym_dec (crypto_sym_t crypto,
		unsigned char ** buffer, size_t * buffer_len,
		const unsigned char * data, size_t len)
{
  EVP_CIPHER_CTX dctx;
  HMAC_CTX hctx;
  unsigned char iv[32], hash[64];
  int ret;
  size_t block_size, pos;

  /* Make sure we have a valid size */
  block_size = EVP_CIPHER_block_size (EVP_aes_256_cbc ());
  if (len < 64 + 32 + block_size || (len-96) % block_size != 0)
    return CRYPTO_INVALID_DATA_SIZE;

  /* Initialize Contexts */
  EVP_CIPHER_CTX_init (&dctx);
  HMAC_CTX_init (&hctx);

  /* Setup Contexts */
  ret = EVP_DecryptInit_ex (&dctx, EVP_aes_256_cbc(), NULL, crypto->key, data);
  if (ret != 1)
    {
      EVP_CIPHER_CTX_cleanup (&dctx);
      HMAC_CTX_cleanup (&hctx);
      return CRYPTO_UNKNOWN;
    }
  ret = HMAC_Init (&hctx, crypto->key, 32, EVP_sha512());
  if (ret != 1)
    {
      EVP_CIPHER_CTX_cleanup (&dctx);
      HMAC_CTX_cleanup (&hctx);
      return CRYPTO_UNKNOWN;
    }

  /* Setup Data */
  len -= 96;
  *buffer = (unsigned char *) malloc (len * sizeof (char));
  
  /* Hash IV Data */
  HMAC_Update (&hctx, data, 32);

  /* Encrypt and Write Data */
  if (EVP_DecryptUpdate (&dctx, *buffer, &ret, data+32, len) == 0)
    {
      EVP_CIPHER_CTX_cleanup (&dctx);
      HMAC_CTX_cleanup (&hctx);
      free (*buffer);
      return CRYPTO_INVALID_DATA;
    }
  *buffer_len = ret;
  ret = 0;
  if (EVP_DecryptFinal_ex (&dctx, *buffer + *buffer_len, &ret) == 0)
    {
      EVP_CIPHER_CTX_cleanup (&dctx);
      HMAC_CTX_cleanup (&hctx);
      free (*buffer);
      return CRYPTO_INVALID_DATA;
    }
  *buffer_len += ret;

  /* Generate HMAC */
  HMAC_Update (&hctx, *buffer, *buffer_len);
  block_size = 64;
  HMAC_Final (&hctx, hash, &ret);

  /* Cleanup */
  EVP_CIPHER_CTX_cleanup (&dctx);
  HMAC_CTX_cleanup (&hctx);

  /* Check HMAC Hash */
  if (strncmp (data+len+32, hash, 64) != 0)
    {
      free (*buffer);
      return CRYPTO_INVALID_DATA;
    }

  return CRYPTO_SUCCESS;
}

crypto_sym_trans_t
crypto_sym_trans_init (const crypto_sym_t crypto)
{
  crypto_sym_trans_t trans;

  /* Create Trans Handle */
  trans = (crypto_sym_trans_t) malloc (sizeof (struct _crypto_sym_trans_t));
  mlock (trans, sizeof (struct _crypto_sym_trans_t));
  EVP_CIPHER_CTX_init (&trans->c_ctx);
  HMAC_CTX_init (&trans->h_ctx);
  trans->initialized = 1;
  trans->finalized = 0;

  /* Copy the Key String */
  memcpy (trans->key, crypto->key, 32);

  return trans;
}

void
crypto_sym_trans_destroy (crypto_sym_trans_t trans)
{
  EVP_CIPHER_CTX_cleanup (&trans->c_ctx);
  HMAC_CTX_cleanup (&trans->h_ctx);
  munlock (trans, sizeof (struct _crypto_sym_trans_t));
  free (trans);
}

enum crypto_status
crypto_sym_dec_setup (crypto_sym_trans_t trans)
{
  int ret;

  /* Setup HMAC */
  ret = HMAC_Init (&trans->h_ctx, trans->key, 32, EVP_sha512());
  if (ret != 1)
    return CRYPTO_UNKNOWN;

  /* Setup struct */
  trans->buffer_len = 0;

  return CRYPTO_SUCCESS;
}

ssize_t
crypto_sym_dec_update (crypto_sym_trans_t trans,
		       unsigned char * buffer, size_t buffer_len,
		       const unsigned char * data, size_t len)
{
  int ret, size;
  size_t processed, block_size, tmp, data_pos;

  /* Check for a large enough buffer */
  if (buffer_len < len)
    return -1;

  /* Make sure it has been initialized */
  data_pos = 0;
  if (trans->initialized == 1)
    {
      if (len + trans->buffer_len < 32)
	block_size = len;
      else
	block_size = 32 - trans->buffer_len;
      memcpy (trans->iv + trans->buffer_len, data, block_size);
      data_pos += block_size;
      trans->buffer_len += block_size;
      if (trans->buffer_len == 32)
	{
	  ret = EVP_DecryptInit_ex (&trans->c_ctx, EVP_aes_256_cbc(),
				    NULL, trans->key, trans->iv);
	  if (ret != 1)
	    return -1;
	  HMAC_Update (&trans->h_ctx, trans->iv, 32);
	  trans->initialized = 0;
	  trans->buffer_len = 0;
	}
      else
	return 0;
    }

  /* Continue Decryption */
  processed = 0;
  if (trans->buffer_len > 0)
    {
      block_size = trans->buffer_len;
      if (block_size > buffer_len)
	block_size = buffer_len;
      ret = EVP_DecryptUpdate (&trans->c_ctx,
			       buffer, &size,
			       trans->buffer, block_size);
      if (ret != 1)
	return -1;
      HMAC_Update (&trans->h_ctx, buffer, size);
      processed += size;
      trans->buffer_len -= block_size;
      if (trans->buffer_len != 0)
	{
	  memmove (trans->buffer, trans->buffer + block_size, trans->buffer_len);
	  return processed;
	}
    }
  if (len - data_pos > 64)
    {
      tmp = len - data_pos - 64;
      ret = EVP_DecryptUpdate (&trans->c_ctx, buffer + processed, &size, data + data_pos, tmp);
      if (ret != 1)
	return -1;
      HMAC_Update (&trans->h_ctx, buffer + processed, size);
      data_pos += tmp;
      processed += size;
    }
  
  memcpy (trans->buffer + trans->buffer_len, data + data_pos, len - data_pos);
  trans->buffer_len += len - data_pos;

  return processed;
}

enum crypto_status
crypto_sym_dec_finalize (crypto_sym_trans_t trans,
			 unsigned char * buffer, size_t * buffer_len)
{
  unsigned char hash[64];
  int ret, size;

  ret = EVP_DecryptFinal_ex (&trans->c_ctx, buffer, &size);
  if (ret != 1)
    return CRYPTO_INVALID_DATA;
  if (size > 0)
    HMAC_Update (&trans->h_ctx, buffer, size);
  *buffer_len = size;
  HMAC_Final (&trans->h_ctx, hash, &ret);
  if (strncmp (hash, trans->buffer, 64) != 0)
    return CRYPTO_INVALID_DATA;
  return CRYPTO_SUCCESS;
}

enum crypto_status
crypto_sym_enc_setup (crypto_sym_trans_t trans)
{
  int ret;

  /* Generate a new IV for encryption */
  trans->buffer_len = 0;
  crypto_sym_genkey (trans->iv, 32);

  /* Setup Ciphers and HMAC */
  ret = EVP_EncryptInit_ex (&trans->c_ctx, EVP_aes_256_cbc(), NULL, trans->key, trans->iv);
  if (ret != 1)
    return CRYPTO_UNKNOWN;
  ret = HMAC_Init (&trans->h_ctx, trans->key, 32, EVP_sha512());
  if (ret != 1)
    return CRYPTO_UNKNOWN;

  return CRYPTO_SUCCESS;
}

ssize_t
crypto_sym_enc_update (crypto_sym_trans_t trans,
		       unsigned char * buffer, size_t * buffer_len,
		       const unsigned char * data, size_t len)
{
  int ret, size;
  size_t block_size, processed, new_len;

  /* Check for initialized data */
  new_len = 0;
  if (trans->initialized == 1)
    {
      HMAC_Update (&trans->h_ctx, trans->iv, 32);
      memcpy (buffer, trans->iv, 32);
      new_len += 32;
      trans->initialized = 0;
    }

  /* Check the buffer */
  if (trans->buffer_len > 0)
    {
      block_size = trans->buffer_len;
      if (block_size > *buffer_len - new_len)
	block_size = *buffer_len - new_len;
      memcpy (buffer + new_len, trans->buffer, block_size);
      new_len += block_size;
      trans->buffer_len -= block_size;
      if (new_len == *buffer_len)
	return 0;
      memmove (trans->buffer, trans->buffer + block_size, trans->buffer_len);
    }

  /* Finalized Checks */
  if (trans->finalized == 1)
    {
      *buffer_len = new_len;
      return 0;
    }

  /* Calculate the proper number of blocks to process */
  processed = 0;
  block_size = len;
  if (len > *buffer_len - new_len)
    block_size = *buffer_len - new_len;

  /* Encrypt all available space */
  HMAC_Update (&trans->h_ctx, data + processed, block_size);
  ret = EVP_EncryptUpdate (&trans->c_ctx, buffer + new_len, &size,
			   data + processed, block_size);
  if (ret != 1)
    return -1;
  new_len += size;
  processed += block_size;

  /* Check for end of buffer */
  if (len == processed && trans->finalized == 0)
    {
      EVP_EncryptFinal_ex (&trans->c_ctx, trans->buffer, &size);
      trans->buffer_len = size;
      HMAC_Final (&trans->h_ctx, trans->buffer + trans->buffer_len, &size);
      trans->buffer_len += size;
      trans->finalized = 1;
    }

  /* Copy buffer into buffer */
  if (*buffer_len > new_len && trans->buffer_len > 0)
    {
      if (trans->buffer_len < *buffer_len - new_len)
	block_size = trans->buffer_len;
      else
	block_size = *buffer_len - new_len;
      memcpy (buffer + new_len, trans->buffer, block_size);
      new_len += block_size;
      trans->buffer_len -= block_size;
      if (trans->buffer_len > 0)
	memmove (trans->buffer, trans->buffer + block_size, trans->buffer_len);
    }

  /* Set the new length of the buffer */
  *buffer_len = new_len;

  return processed;
}

enum crypto_status
crypto_sym_enc_finalize (crypto_sym_trans_t trans)
{
  return CRYPTO_SUCCESS;
}

size_t crypto_sym_enc_size (size_t size)
{
  size_t block_size, offset;

  /* Retreive Block Size */
  block_size = EVP_CIPHER_block_size (EVP_aes_256_cbc ());
  
  /* Calculate Return Size */
  offset = size%block_size;
  if (offset != 0)
    offset = block_size - offset;
  size += offset + 64 + 32;
  
  return size;
}
