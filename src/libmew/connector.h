/* Generic Connector Implementation
   Use this in your connector abstraction */

#ifndef _CONNECTOR_H_
#define _CONNECTOR_H_

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "crypto.h"

enum connector
  {
    CONNECTOR_SUCCESS = 0,
    CONNECTOR_DOESNT_EXIST,
    CONNECTOR_INVALID_TIMESTAMP,
    CONNECTOR_INVALID_FILE,
    CONNECTOR_UNKNOWN
  };

typedef struct _connector_t * connector_t;

/* Global Function */
void connector_global_init (const unsigned char * type);

void connector_global_cleanup (const unsigned char * type);

/* Initializes a connector by name of connection. Returns NULL on failure */
int connector_init (connector_t * c, const unsigned char * type);

/* Connects the connector to the specified website url */
int connector_connect (connector_t c, const unsigned char * url,
		       const unsigned char * user, const unsigned char * pass);

int connector_get (connector_t c, const unsigned char * obj,
		   void ** data, size_t * size, size_t * len,
		   crypto_sym_t crypto);

int connector_put (connector_t c, const unsigned char * obj,
		   const void * data, size_t len,
		   crypto_sym_t crypto);

int connector_get_file (connector_t c, const unsigned char * obj,
			const unsigned char * file, crypto_sym_t crypto);

int connector_put_file (connector_t c, const unsigned char * obj,
			const unsigned char * file, crypto_sym_t crypto);

int connector_get_timestamp (connector_t c, const unsigned char * obj, time_t * time);

int connector_acquire_lock (connector_t c, const unsigned char * obj);

int connector_release_lock (connector_t c, const unsigned char * obj);

/* Disconnects the connector */
void connector_disconnect (connector_t c);

/* Frees all memory associated with the connector */
void connector_destroy (connector_t c);

#endif
