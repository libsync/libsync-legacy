/* Neon based webdav connector to enable webdav uploading
Uses the standard connector reference */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>

#include "connector.h"
#include "curl.h"

#include "connector_ftp.h"

typedef struct _connector_ftp_t
{
} * connector_ftp_t;

/* Useful Global Functions */
void
connector_ftp_global_init ()
{
  if (_curl_init == 0)
    {
      curl_global_init (CURL_GLOBAL_SSL);
      _curl_init = 1;
    }
}

void
connector_ftp_global_cleanup ()
{
  if (_curl_cleanup == 0)
    {
      curl_global_cleanup ();
      _curl_cleanup = 1;
    }
}

/* Connect */
int
connector_ftp_connect (void ** cdata, const unsigned char * url,
		       const unsigned char * user, const unsigned char * pass)
{
  connector_ftp_t c;

  /* Release old connection */
  if(*cdata != NULL)
    connector_ftp_disconnect (*cdata);

  /* Create Object */
  c = (connector_ftp_t)malloc (sizeof (struct _connector_ftp_t));
  *cdata = c;

  return CONNECTOR_SUCCESS;
}

int
connector_ftp_get (void * cdata, const unsigned char * obj,
		   void ** data, size_t * size, size_t * len,
		   crypto_sym_t crypto)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_put (void * cdata, const unsigned char * obj,
		   const void * data, size_t len,
		   crypto_sym_t crypto)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_get_file (void * cdata, const unsigned char * obj,
			const unsigned char * file, crypto_sym_t crypto)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_put_file (void * cdata, const unsigned char * obj,
			const unsigned char * file, crypto_sym_t crypto)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_get_timestamp (void * cdata, const unsigned char * obj, time_t * time)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_acquire_lock (void * cdata, const unsigned char * obj)
{
  return CONNECTOR_UNKNOWN;
}

int
connector_ftp_release_lock (void * cdata, const unsigned char * obj)
{
  return CONNECTOR_UNKNOWN;
}

void
connector_ftp_disconnect (void * cdata)
{
  free(cdata);
}
