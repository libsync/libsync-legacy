/* Generic Implementation of the connector
   Allows easy interchangablity from one protocol to another */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto.h"
#include "connector.h"
#include "connector_webdav.h"
#include "connector_ftp.h"

struct _connector_t
{
  int (*connect) (void **, const unsigned char *, const unsigned char *, const unsigned char *);
  int (*get) (void *, const unsigned char *, void **, size_t *, size_t *, crypto_sym_t);
  int (*put) (void *, const unsigned char *, const void *, size_t, crypto_sym_t);
  int (*get_file) (void *, const unsigned char *, const unsigned char *, crypto_sym_t);
  int (*put_file) (void *, const unsigned char *, const unsigned char *, crypto_sym_t);
  int (*get_timestamp) (void *, const unsigned char *, time_t *);
  int (*acquire_lock) (void *, const unsigned char *);
  int (*release_lock) (void *, const unsigned char*);
  void (*disconnect) (void *);
  void * data;
};

/* Global Functions */
void
connector_global_init (const unsigned char * type)
{
  if (strcmp (type, "webdav") == 0)
    connector_webdav_global_init();
  else if (strcmp (type, "ftp") == 0)
    connector_ftp_global_init();
}

void
connector_global_cleanup (const unsigned char * type)
{
  if (strcmp (type, "webdav") == 0)
    connector_webdav_global_cleanup();
  else if (strcmp (type, "ftp") == 0)
    connector_ftp_global_cleanup();
}

/* Functor Overrides */
/***
    Virtual Constructor:
    
    Sets up a connection object with the proper function pointers
    
    connect: based url, sets up the connector. For example a webdav instance in the root dir of url
    get: returns data, sizeof buf, length of data from server
    put: sends data, sizeof buf, length of data to server
    get_file: gets data from server in puts it into inputted file
    put_file: takes local file and pushes it to server
    get_timestamp: use your imagination (time_t)
    acquire_lock: trys to attain lock from server
    release_lock: releases lock
    disconnect: closes and cleans up connector
 */
int
connector_init (connector_t * c, const unsigned char * type)
{
  *c = (connector_t) malloc (sizeof (struct _connector_t));
  if (strcmp (type, "webdav") == 0)
    {
      (*c)->connect = connector_webdav_connect;
      (*c)->get = connector_webdav_get;
      (*c)->put = connector_webdav_put;
      (*c)->get_file = connector_webdav_get_file;
      (*c)->put_file = connector_webdav_put_file;
      (*c)->get_timestamp = connector_webdav_get_timestamp;
      (*c)->acquire_lock = connector_webdav_acquire_lock;
      (*c)->release_lock = connector_webdav_release_lock;
      (*c)->disconnect = connector_webdav_disconnect;
      (*c)->data = NULL;
    }
  else if (strcmp (type, "ftp") == 0)
    {
      (*c)->connect = connector_ftp_connect;
      (*c)->get = connector_ftp_get;
      (*c)->put = connector_ftp_put;
      (*c)->get_file = connector_ftp_get_file;
      (*c)->put_file = connector_ftp_put_file;
      (*c)->get_timestamp = connector_ftp_get_timestamp;
      (*c)->acquire_lock = connector_ftp_acquire_lock;
      (*c)->release_lock = connector_ftp_release_lock;
      (*c)->disconnect = connector_ftp_disconnect;
      (*c)->data = NULL;
    }
  else
    {
      free (*c);
      *c = NULL;
      return 1;
    }
  return 0;
}

int
connector_connect (connector_t c, const unsigned char * url, const unsigned char * user, const unsigned char * pass)
{
  return c->connect (&c->data, url, user, pass);
}

int
connector_get (connector_t c, const unsigned char * obj,
	       void ** data, size_t * size, size_t * len,
	       crypto_sym_t crypto)
{
  return c->get (c->data, obj, data, size, len, crypto);
}

int
connector_put (connector_t c, const unsigned char * obj,
	       const void * data, size_t len,
	       crypto_sym_t crypto)
{
  return c->put (c->data, obj, data, len, crypto);
}

int
connector_get_file (connector_t c, const unsigned char * obj,
		    const unsigned char * file, crypto_sym_t crypto)
{
  return c->get_file (c->data, obj, file, crypto);
}

int
connector_put_file (connector_t c, const unsigned char * obj,
		    const unsigned char * file, crypto_sym_t crypto)
{
  return c->put_file (c->data, obj, file, crypto);
}

int
connector_get_timestamp (connector_t c, const unsigned char * obj, time_t * time)
{
  return c->get_timestamp (c->data, obj, time);
}

int
connector_acquire_lock (connector_t c, const unsigned char * obj)
{
  return c->acquire_lock (c->data, obj);
}

int
connector_release_lock (connector_t c, const unsigned char * obj)
{
  return c->release_lock (c->data, obj);
}

void
connector_disconnect (connector_t c)
{
  c->disconnect (c->data);
  c->data = NULL;
}

void
connector_destroy (connector_t c)
{
  if (c->data != NULL)
    {
      c->disconnect (c->data);
      c->data = NULL;
    }
  free (c);
}
