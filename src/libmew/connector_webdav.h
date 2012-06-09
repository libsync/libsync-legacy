/* Webdav Connector Interface
 DO NOT USE THIS UNLESS YOU KNOW WHAT YOU ARE DOING*/

#ifndef _CONNECTOR_WEBDAV_H_
#define _CONNECTOR_WEBDAV_H_

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "crypto.h"

/* Global Functions */
void connector_webdav_global_init ();

void connector_webdav_global_cleanup ();

/* Connects to the webdav url */
int connector_webdav_connect (void ** cdata, const unsigned char * url,
			      const unsigned char * user, const unsigned char * pass);

int connector_webdav_get (void * cdata, const unsigned char * obj,
			  void ** data, size_t * size, size_t * len,
			  crypto_sym_t crypto);

int connector_webdav_put (void * cdata, const unsigned char * obj,
			  const void * data, size_t len,
			  crypto_sym_t crypto);

int connector_webdav_get_file (void * cdata, const unsigned char * obj,
			       const unsigned char * file, crypto_sym_t crypto);

int connector_webdav_put_file (void * cdata, const unsigned char * obj,
			       const unsigned char * file, crypto_sym_t crypto);

int connector_webdav_get_timestamp (void * cdata, const unsigned char * obj, time_t * time);

int connector_webdav_acquire_lock (void * cdata, const unsigned char * obj);

int connector_webdav_release_lock (void * cdata, const unsigned char * obj);

/* Disconnects the connector */
void connector_webdav_disconnect (void * cdata);

#endif
