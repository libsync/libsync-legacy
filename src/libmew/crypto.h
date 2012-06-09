#ifndef _CRYPTO_H_
#define _CRYPTO_H_

enum crypto_status
  {
    CRYPTO_SUCCESS = 0,
    CRYPTO_INVALID_KEY,
    CRYPTO_INVALID_DATA_SIZE,
    CRYPTO_INVALID_DATA,
    CRYPTO_UNKNOWN
  };

typedef struct _crypto_sym_t *crypto_sym_t;
typedef struct _crypto_sym_trans_t *crypto_sym_trans_t;

/* Useful Helpers */
volatile void crypto_secure_erase (volatile void * data, size_t len);
void crypto_sym_genkey (unsigned char * key, size_t len);
unsigned char * crypto_bytes_to_hex (const unsigned char * bytes, size_t len);
unsigned char * crypto_hex_to_bytes (const unsigned char * hex, size_t * olen);

/* Message Digest, Returns bytes of hash */
unsigned char * crypto_sha256 (const unsigned char * bytes, size_t len, size_t * olen);
unsigned char * crypto_sha512 (const unsigned char * bytes, size_t len, size_t * olen);

/* Initializes the crypto struct with key and key_len */
enum crypto_status crypto_sym_init (crypto_sym_t * crypto, const unsigned char * key, size_t key_len, int hash);
void crypto_sym_destroy (crypto_sym_t crypto);

/* Crypt in one go */
enum crypto_status crypto_sym_enc (crypto_sym_t crypto,
				   unsigned char ** buffer, size_t * buffer_len,
				   const unsigned char * data, size_t len);
enum crypto_status crypto_sym_dec (crypto_sym_t crypto,
				   unsigned char ** buffer, size_t * buffer_len,
				   const unsigned char * data, size_t len);

/* Crypt handle */
crypto_sym_trans_t
crypto_sym_trans_init (const crypto_sym_t crypto);

void crypto_sym_trans_destroy (crypto_sym_trans_t trans);

enum crypto_status
crypto_sym_dec_setup (crypto_sym_trans_t trans);

ssize_t
crypto_sym_dec_update (crypto_sym_trans_t trans,
		       unsigned char * buffer, size_t buffer_len,
		       const unsigned char * data, size_t len);
enum crypto_status
crypto_sym_dec_finalize (crypto_sym_trans_t trans,
			 unsigned char * buffer, size_t * buffer_len);

enum crypto_status
crypto_sym_enc_setup (crypto_sym_trans_t trans);

ssize_t
crypto_sym_enc_update (crypto_sym_trans_t trans,
		       unsigned char * buffer, size_t * buffer_len,
		       const unsigned char * data, size_t len);

enum crypto_status
crypto_sym_enc_finalize (crypto_sym_trans_t trans);

size_t crypto_sym_enc_size (size_t in_size);

#endif
