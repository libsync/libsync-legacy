#ifndef _METADATA_H_
#define _METADATA_H_

#include "connector.h"

enum metadata_update
  {
    METADATA_SUCCESS = 0,
    METADATA_UP_TO_DATE,
    METADATA_DOWNLOAD_FAILED,
    METADATA_INVALID_VERSION,
    METADATA_PUSH_FAILED,
    METADATA_INVALID
  };

typedef struct _metadata_t *metadata_t;

typedef struct _metadata_entry_t
{
  char * filename, objname[65];
  unsigned long mark, timestamp;
  char updated, deleted;
} metadata_entry_t;

/* Initializes a new Metadata Structure */
void metadata_init (metadata_t * data);

/* Populates and updates the data in the metadata structure
   with new data from the server */
enum metadata_update
metadata_update_put (metadata_t data, connector_t conn,
		 crypto_sym_t crypto);

enum metadata_update
metadata_update_get (metadata_t data, connector_t conn,
		 crypto_sym_t crypto);

/* Blocks until updates are available
   from the remote server.
   Calls metadata_update after blocking */
enum metadata_update
metadata_wait_update (metadata_t data, connector_t conn,
		      crypto_sym_t crypto);

/* Retrieves information about a remote file stored 
   On the server */
ssize_t metadata_get_index (metadata_t data, const char * filename);
metadata_entry_t *metadata_get_entry (metadata_t data, size_t index);

/* Inserts a new entry into the metadata list */
metadata_entry_t *metadata_insert (metadata_t data);

/* Gets the size of the list */
size_t metadata_len (metadata_t data);

/* Cleans up dynamically allocated memory from metadata */
void metadata_destroy (metadata_t data);

void metadata_print (metadata_t data);

int metadata_object_name (metadata_entry_t * entry, char * filename);

#endif
