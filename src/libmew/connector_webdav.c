/* Neon based webdav connector to enable webdav uploading
Uses the standard connector reference */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "connector.h"
#include "curl.h"

#include "connector_webdav.h"

#define BUFFER_SIZE 64

typedef struct _connector_webdav_t
{
  CURL *handle;
  unsigned char *dir_url;
  size_t dir_len;
  unsigned char *user_pass;
} * connector_webdav_t;


/* Static Helpers */

struct connector_webdav_data
{
  void *data;
  size_t size, len;
  crypto_sym_trans_t crypto;
};

struct connector_webdav_datar
{
  const void *data;
  size_t size;
  crypto_sym_trans_t crypto;
};

struct connector_webdav_dataf
{
  FILE *file;
  crypto_sym_trans_t crypto;
  unsigned char * buffer;
  size_t buffer_len, buffer_size;
};

static unsigned char *
connector_webdav_assemble_url (const unsigned char *url, size_t url_len, const unsigned char *obj)
{
  size_t size_obj;
  unsigned char *ret;

  size_obj = strlen (obj)*sizeof (char);
  ret = (unsigned char*)malloc (url_len * sizeof (char) + size_obj + sizeof (char));
  memcpy (ret, url, url_len * sizeof (char));
  memcpy (ret + url_len, obj, size_obj + sizeof (char));

  return ret;
}

static size_t
connector_webdav_read_data (void *ptr, size_t size, size_t nmemb, void *data)
{
  struct connector_webdav_datar *curl_data;
  ssize_t processed;
  
  /* Setup Curl Data */
  curl_data = (struct connector_webdav_datar *)data;
  size *= nmemb;

  /* Write Data If Size > 0 */
  if (size <= 0)
    return 0;

  processed = size;
  if (curl_data->crypto == NULL)
    {
      /* Determine Proper Size to Write */
      if (size > curl_data->size)
	size = curl_data->size;
      memcpy (ptr, curl_data->data, size);
    }
  else
    {
      processed = crypto_sym_enc_update (curl_data->crypto,
					 ptr, &size,
					 curl_data->data, curl_data->size);
      if (processed == -1)
	return 0;
    }

  /* Fix Struct */
  curl_data->data = (char*)curl_data->data + processed;
  curl_data->size -= processed;

  return size;
}

static size_t
connector_webdav_write_data (char *ptr, size_t size, size_t nmemb, void *data)
{
  struct connector_webdav_data *curl_data;
  ssize_t processed;

  /* Setup Curl Data */
  curl_data = (struct connector_webdav_data *)data;
  size *= nmemb;

  /* Non-zero Check */
  if (size == 0)
    return size;

  /* Resize data accordingly */
  if (curl_data->len + size >= curl_data->size)
    {
      while (curl_data->len + size >= curl_data->size)
	curl_data->size <<= 1;
      curl_data->data = realloc (curl_data->data, curl_data->size);
    }

  /* Copy the data to the buffer */
  if (curl_data->crypto == NULL)
    {
      memcpy ((char *)curl_data->data + curl_data->len, ptr, size);
      curl_data->len += size;
    }
  else
    {
      processed = crypto_sym_dec_update (curl_data->crypto,
					 curl_data->data + curl_data->len,
					 curl_data->size - curl_data->len,
					 ptr, size);
      if (processed == -1)
	return 0;
      curl_data->len += processed;
    }

  return size;
}

static size_t
connector_webdav_read_file (char *ptr, size_t size, size_t nmemb, void * data)
{
  struct connector_webdav_dataf *curl_data;
  size_t read;

  /* Setup Data Segment */
  curl_data = (struct connector_webdav_dataf *) data;
  size *= nmemb;

  /* Non-zero Check */
  if (size == 0)
    return size;
  
  /* Make sure buffer is large enough */
  if (curl_data->buffer_size < size + 64)
    {
      curl_data->buffer_size = size + 64;
      curl_data->buffer = (unsigned char *) realloc (curl_data->buffer, curl_data->buffer_size);
    }

  /* Read the file into the buffer */
  if (curl_data->buffer_size > curl_data->buffer_len)
    {
      read = fread (curl_data->buffer + curl_data->buffer_len,
		    sizeof (char), curl_data->buffer_size - curl_data->buffer_len,
		    curl_data->file);
      if (read > 0)
	curl_data->buffer_len += read;
    }

  /* Write the contents to the ptr */
  if (curl_data->crypto == NULL)
    {
      if (curl_data->buffer_len < size)
	read = curl_data->buffer_len;
      else
	read = size;
      memcpy (ptr, curl_data->buffer, read);
      curl_data->buffer_len -= read;
      if (curl_data->buffer_len > 0)
	memmove (curl_data->buffer,
		 curl_data->buffer + read,
		 curl_data->buffer_len);
    }
  else
    {
      read = crypto_sym_enc_update (curl_data->crypto,
				    ptr, &size,
				    curl_data->buffer, curl_data->buffer_len);
      curl_data->buffer_len -= read;
      if (curl_data->buffer_len  > 0)
	memmove (curl_data->buffer,
		 curl_data->buffer + read,
		 curl_data->buffer_len);
      read = size;
    }
  
  return read;
}

static size_t
connector_webdav_write_file (char *ptr, size_t size, size_t nmemb, void *data)
{
  struct connector_webdav_dataf *curl_data;
  ssize_t read;

  /* Setup Data Segment */
  curl_data = (struct connector_webdav_dataf *) data;
  size *= nmemb;

  /* Non-zero Check */
  if (size == 0)
    return size;

  /* Make sure buffer is large enough */
  if (curl_data->buffer_size < size)
    {
      curl_data->buffer_size = size;
      curl_data->buffer = (unsigned char *) realloc (curl_data->buffer, curl_data->buffer_size);
    }

  /* Move data from the read */
  if (curl_data->crypto == NULL)
    fwrite (ptr, sizeof (char), size, curl_data->file);
  else
    {
      read = crypto_sym_dec_update (curl_data->crypto,
				    curl_data->buffer, curl_data->buffer_size,
				    ptr, size);
      if (read < 0)
	return 0;

      /* Write data to the file */
      fwrite (curl_data->buffer, sizeof (char), read, curl_data->file);
    }


  return size;
}

static time_t
connector_webdav_xml_to_time (const char * str)
{
  struct tm tm;
  memset (&tm, 0, sizeof (struct tm));
  if (strptime (str, "%a, %d %b %Y %H:%M:%S", &tm))
    return mktime (&tm);
 if (strptime (str, "%Y-%m-%dT%H:%M:%SZ", &tm))
    return mktime (&tm);
  return -1;
}

static xmlNode *
connector_webdav_xml_get (xmlNode * node, const char * name)
{
  xmlNode * ret;
  while (node != NULL)
    {
      if (node->type == XML_ELEMENT_NODE && xmlStrcmp (node->name, name) == 0)
	return node;
      ret = connector_webdav_xml_get (node->children, name);
      if (ret != NULL)
	return ret;
      node = node->next;
    }
  return NULL;
}

/* Useful Globals */
void
connector_webdav_global_init ()
{
  if (_curl_init == 0)
    {
      curl_global_init (CURL_GLOBAL_SSL);
      _curl_init = 1;
    }
}

void
connector_webdav_global_cleanup ()
{
  
  if (_curl_cleanup == 0)
    {
      xmlCleanupParser ();
      curl_global_cleanup ();
      _curl_cleanup = 1;
    }
}

/* Connect */
int
connector_webdav_connect (void ** cdata, const unsigned char * url,
			  const unsigned char * user, const unsigned char * pass)
{
  connector_webdav_t c;
  CURLcode res;
  FILE *null_file;
  size_t user_len, pass_len;

  /* Release old connection */
  if(*cdata != NULL)
    connector_webdav_disconnect (*cdata);

  /* Create Object */
  c = (connector_webdav_t)malloc (sizeof (struct _connector_webdav_t));
  *cdata = c;

  /* Setup curl handle */
  c->handle = curl_easy_init ();
  if (c->handle == NULL)
    return -1;

  /* Parse Username and Password */
  if (user != NULL && pass != NULL)
    {
      user_len = strlen (user);
      pass_len = strlen (pass);
      c->user_pass = (unsigned char *)malloc ((user_len + pass_len + 2) * sizeof (char));
      memcpy (c->user_pass, user, user_len * sizeof (char));
      c->user_pass[user_len] = ':';
      memcpy (c->user_pass + user_len + 1, pass, pass_len * sizeof (char));
      c->user_pass[user_len + 1 + pass_len] = 0;
    }
  else
    c->user_pass = NULL;

  /* Copy url string and append a "/" to the end */
  c->dir_len = strlen (url);
  if (url[c->dir_len - 1] != '/')
    {
      /* Add room for "/" */
      c->dir_len += 1;

      c->dir_url = (unsigned char *)malloc ((c->dir_len + 1) * sizeof (char));
      memcpy (c->dir_url, url, (c->dir_len - 1) * sizeof (char));
      c->dir_url[c->dir_len-1] = '/';
      c->dir_url[c->dir_len] = 0;
    }
  else
    {
      c->dir_url = (unsigned char *)malloc ((c->dir_len + 1) * sizeof (char));
      memcpy (c->dir_url, url, (c->dir_len + 1) * sizeof (char));
    }

  return CONNECTOR_SUCCESS;
}

int
connector_webdav_get (void * cdata, const unsigned char * obj,
		      void ** data, size_t * size, size_t * len,
		      crypto_sym_t crypto)
{
  connector_webdav_t c;
  unsigned char *url;
  CURLcode res;
  struct connector_webdav_data curl_data;
  long response_code;
  size_t ret;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  /* Assemble URL String */
  url = connector_webdav_assemble_url (c->dir_url, c->dir_len, obj);

  /* Setup Curl Data Struct */
  curl_data.data = *data;
  curl_data.size = *size;
  if (curl_data.data == NULL)
    {
      curl_data.size = BUFFER_SIZE;
      curl_data.data = malloc (curl_data.size);
    }
  curl_data.len = 0;
  curl_data.crypto = NULL;

  /* If necessary Initialize Crypto */
  if (crypto != NULL)
    {
      curl_data.crypto = crypto_sym_trans_init (crypto);
      crypto_sym_dec_setup (curl_data.crypto);
    }

  /* Run Curl */
  curl_easy_setopt (c->handle, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt (c->handle, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt (c->handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt (c->handle, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt (c->handle, CURLOPT_URL, url);
  if (c->user_pass != NULL)
    curl_easy_setopt (c->handle, CURLOPT_USERPWD, c->user_pass);
  curl_easy_setopt (c->handle, CURLOPT_WRITEFUNCTION, connector_webdav_write_data);
  curl_easy_setopt (c->handle, CURLOPT_WRITEDATA, &curl_data);
  res = curl_easy_perform (c->handle);
  curl_easy_reset (c->handle);
  free(url);

  /* If necessary Finalize Crypto */
  if (curl_data.crypto != NULL)
    {
      /* Make sure the buffer is large enough */
      if (curl_data.size - curl_data.len < 64)
	{
	  curl_data.size += 64;
	  curl_data.data = (char *) realloc (curl_data.data, curl_data.size);
	}
      if (crypto_sym_dec_finalize (curl_data.crypto,
				   curl_data.data + curl_data.len,
				   &ret) != CRYPTO_SUCCESS)
	{
	  if(curl_data.data != *data)
	    free(curl_data.data);
	  crypto_sym_trans_destroy (curl_data.crypto);
	  return CONNECTOR_UNKNOWN;
	}
      curl_data.len += ret;
      crypto_sym_trans_destroy (curl_data.crypto);
    }

  /* Check for Curl Errors */
  if (res != 0)
    {
      /* Free Unused Data */
      if(curl_data.data != *data)
	free(curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Response Code */
  if (curl_easy_getinfo (c->handle, CURLINFO_RESPONSE_CODE, &response_code))
    {
      /* Free Unused Data */
      if(curl_data.data != *data)
	free(curl_data.data);
      return CONNECTOR_UNKNOWN;
    }
  if (response_code == 404)
    {
      /* Free Unused Data */
      if(curl_data.data != *data)
	free(curl_data.data);
      return CONNECTOR_DOESNT_EXIST;
    }
  if (response_code < 200 || response_code > 299)
    {
      /* Free Unused Data */
      if(curl_data.data != *data)
	free(curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Copy Struct Info */
  *data = curl_data.data;
  *size = curl_data.size;
  *len = curl_data.len;

  return CONNECTOR_SUCCESS;
}

int
connector_webdav_put (void * cdata, const unsigned char * obj,
		      const void * data, size_t len,
		      crypto_sym_t crypto)
{
  connector_webdav_t c;
  unsigned char *url;
  CURLcode res;
  struct connector_webdav_datar curl_datar;
  struct connector_webdav_data curl_data;
  long response_code;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  /* Assemble URL String */
  url = connector_webdav_assemble_url (c->dir_url, c->dir_len, obj);

  /* Setup Curl Data Structs */
  curl_datar.data = data;
  curl_datar.size = len;
  curl_datar.crypto = NULL;

  curl_data.size = BUFFER_SIZE;
  curl_data.data = malloc (curl_data.size);
  curl_data.len = 0;
  curl_data.crypto = NULL;

  /* Initialize Crypto */
  if (crypto != NULL)
    {
      curl_datar.crypto = crypto_sym_trans_init (crypto);
      len = crypto_sym_enc_size (len);
      crypto_sym_enc_setup (curl_datar.crypto);
    }

  /* Run Curl */
  curl_easy_setopt (c->handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)len);
  curl_easy_setopt (c->handle, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt (c->handle, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt (c->handle, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt (c->handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt (c->handle, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt (c->handle, CURLOPT_URL, url);
  if (c->user_pass != NULL)
    curl_easy_setopt (c->handle, CURLOPT_USERPWD, c->user_pass);
  curl_easy_setopt (c->handle, CURLOPT_READFUNCTION, connector_webdav_read_data);
  curl_easy_setopt (c->handle, CURLOPT_READDATA, &curl_datar);
  curl_easy_setopt (c->handle, CURLOPT_WRITEFUNCTION, connector_webdav_write_data);
  curl_easy_setopt (c->handle, CURLOPT_WRITEDATA, &curl_data);
  res = curl_easy_perform (c->handle);
  curl_easy_reset (c->handle);
  free(url);

  /* Finalize Crypto */
  if (curl_datar.crypto != NULL)
    {
      if (crypto_sym_enc_finalize (curl_datar.crypto) != CRYPTO_SUCCESS)
	{
	  free (curl_data.data);
	  crypto_sym_trans_destroy (curl_datar.crypto);
	  return CONNECTOR_UNKNOWN;
	}
      crypto_sym_trans_destroy (curl_datar.crypto);
    }

  /* Check for Curl Errors */
  if (res != 0)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Response Code */
  if (curl_easy_getinfo (c->handle, CURLINFO_RESPONSE_CODE, &response_code))
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }
  if (response_code == 404)
    {
      free (curl_data.data);
      return CONNECTOR_DOESNT_EXIST;
    }
  if (response_code < 200 || response_code > 299)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Additional Parameters */

  free (curl_data.data);
  return CONNECTOR_SUCCESS;
}

/*
 NOTE THIS WILL DESTROY THE LOCAL FILE IF IT FAILS, TMPFILES ARE RECOMMENDED
*/
int
connector_webdav_get_file (void * cdata, const unsigned char * obj,
			   const unsigned char * file, crypto_sym_t crypto)
{
  connector_webdav_t c;
  unsigned char *url;
  CURLcode res;
  FILE *file_handle;
  long response_code;
  char *response_type, buffer[128];
  size_t buffer_len;
  struct connector_webdav_dataf curl_data;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  /* Open File Handle */
  file_handle = fopen (file, "wb");
  if (file_handle == NULL)
    return CONNECTOR_INVALID_FILE;

  /* Assemble URL String */
  url = connector_webdav_assemble_url (c->dir_url, c->dir_len, obj);

  /* Assemble Data Struct */
  curl_data.file = file_handle;
  curl_data.crypto = NULL;
  curl_data.buffer = NULL;
  curl_data.buffer_len = 0;
  curl_data.buffer_size = 0;

  /* Setup Crypto */
  if (crypto != NULL)
    {
      curl_data.crypto = crypto_sym_trans_init (crypto);
      crypto_sym_dec_setup (curl_data.crypto);
    }

  /* Run Curl */
  curl_easy_setopt (c->handle, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt (c->handle, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt (c->handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt (c->handle, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt (c->handle, CURLOPT_URL, url);
  if (c->user_pass != NULL)
    curl_easy_setopt (c->handle, CURLOPT_USERPWD, c->user_pass);
  curl_easy_setopt (c->handle, CURLOPT_WRITEFUNCTION, connector_webdav_write_file);
  curl_easy_setopt (c->handle, CURLOPT_WRITEDATA, &curl_data);
  res = curl_easy_perform (c->handle);
  curl_easy_reset (c->handle);
  free(url);

  if (curl_data.buffer != NULL)
    free (curl_data.buffer);

  /* Finalize Crypto */
  if (curl_data.crypto != NULL)
    {
      if (crypto_sym_dec_finalize (curl_data.crypto, buffer, &buffer_len) != CRYPTO_SUCCESS)
	{
	  crypto_sym_trans_destroy (curl_data.crypto);
	  fclose (file_handle);
	  return CONNECTOR_UNKNOWN;
	}
      fwrite (buffer, sizeof (char), buffer_len, file_handle);
      crypto_sym_trans_destroy (curl_data.crypto);
    }

  fclose (file_handle);

  /* Check for Curl Errors */
  if (res != 0)
    return CONNECTOR_UNKNOWN;

  /* Check Response Code */
  if (curl_easy_getinfo (c->handle, CURLINFO_RESPONSE_CODE, &response_code))
    return CONNECTOR_UNKNOWN;
  if (response_code == 404)
    return CONNECTOR_DOESNT_EXIST;
  if (response_code < 200 || response_code > 299)
    return CONNECTOR_UNKNOWN;

  return CONNECTOR_SUCCESS;
}

int
connector_webdav_put_file (void * cdata, const unsigned char * obj,
			   const unsigned char * file, crypto_sym_t crypto)
{
  connector_webdav_t c;
  unsigned char *url;
  CURLcode res;
  FILE *file_handle;
  struct stat file_stats;
  struct connector_webdav_data curl_data;
  struct connector_webdav_dataf curl_dataf;
  long response_code;
  size_t len;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  /* Try and Stat the File */
  if (stat (file, &file_stats))
    return CONNECTOR_INVALID_FILE;

  /* Open the handle to the file */
  file_handle = fopen (file, "rb");
  if (file_handle == NULL)
    return CONNECTOR_INVALID_FILE;

  /* Assemble URL String */
  url = connector_webdav_assemble_url (c->dir_url, c->dir_len, obj);

  /* Setup Curl Data Structs */
  curl_data.size = BUFFER_SIZE;
  curl_data.data = malloc (curl_data.size);
  curl_data.len = 0;
  curl_data.crypto = NULL;

  curl_dataf.file = file_handle;
  curl_dataf.crypto = NULL;
  curl_dataf.buffer = NULL;
  curl_dataf.buffer_len = 0;
  curl_dataf.buffer_size = 0;

  /* Setup Crypto */
  len = file_stats.st_size;
  if (crypto != NULL)
    {
      curl_dataf.crypto = crypto_sym_trans_init (crypto);
      crypto_sym_enc_setup (curl_dataf.crypto);
      len = crypto_sym_enc_size (len);
    }

  /* Run Curl */
  curl_easy_setopt (c->handle, CURLOPT_INFILESIZE_LARGE, (curl_off_t)len);
  curl_easy_setopt (c->handle, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt (c->handle, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt (c->handle, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt (c->handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt (c->handle, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt (c->handle, CURLOPT_URL, url);
  if (c->user_pass != NULL)
    curl_easy_setopt (c->handle, CURLOPT_USERPWD, c->user_pass);
  curl_easy_setopt (c->handle, CURLOPT_READFUNCTION, connector_webdav_read_file);
  curl_easy_setopt (c->handle, CURLOPT_READDATA, &curl_dataf);
  curl_easy_setopt (c->handle, CURLOPT_WRITEFUNCTION, connector_webdav_write_data);
  curl_easy_setopt (c->handle, CURLOPT_WRITEDATA, &curl_data);
  res = curl_easy_perform (c->handle);
  curl_easy_reset (c->handle);
  fclose (file_handle);
  free(url);

  if (curl_dataf.buffer != NULL)
    free (curl_dataf.buffer);

  /* Finalize Crypto */
  if (curl_dataf.crypto != NULL)
    {
      crypto_sym_enc_finalize (curl_dataf.crypto);
      crypto_sym_trans_destroy (curl_dataf.crypto);
    }

  /* Check for Curl Errors */
  if (res != 0)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Response Code */
  if (curl_easy_getinfo (c->handle, CURLINFO_RESPONSE_CODE, &response_code))
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }
  if (response_code == 404)
    {
      free (curl_data.data);
      return CONNECTOR_DOESNT_EXIST;
    }
  if (response_code < 200 || response_code > 299)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Additional Parameters */

  free (curl_data.data);
  return CONNECTOR_SUCCESS;
}

int
connector_webdav_get_timestamp (void * cdata, const unsigned char * obj, time_t * time)
{
  connector_webdav_t c;
  unsigned char *url;
  CURLcode res;
  struct connector_webdav_data curl_data;
  long response_code;
  char *response_type, *request_xml;
  struct curl_slist *request_headers;
  xmlDoc *xml_doc;
  xmlNode *xml_root, *xml_elem;
  xmlChar *xml_str;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  /* Assemble URL String */
  url = connector_webdav_assemble_url (c->dir_url, c->dir_len, obj);

  /* Setup Curl Data Structs */
  curl_data.size = BUFFER_SIZE;
  curl_data.data = malloc (curl_data.size);
  curl_data.len = 0;
  curl_data.crypto = NULL;

  /* Setup CURL */
  curl_easy_setopt (c->handle, CURLOPT_POST, 1L);
  curl_easy_setopt (c->handle, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt (c->handle, CURLOPT_MAXREDIRS, 50L);
  curl_easy_setopt (c->handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt (c->handle, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt (c->handle, CURLOPT_URL, url);
  if (c->user_pass != NULL)
    curl_easy_setopt (c->handle, CURLOPT_USERPWD, c->user_pass);
  curl_easy_setopt (c->handle, CURLOPT_WRITEFUNCTION, connector_webdav_write_data);
  curl_easy_setopt (c->handle, CURLOPT_WRITEDATA, &curl_data);

  /* Setup POST Data */
  //request_xml = "<?xml version=\"1.0\" ?><D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>";
  request_xml = "<?xml version=\"1.0\" ?><D:propfind xmlns:D=\"DAV:\"><a:prop><a:getlastmodified/></a:prop></D:propfind>";
  curl_easy_setopt (c->handle, CURLOPT_POSTFIELDS, request_xml);

  /* Setup Request Headers */
  request_headers = NULL;
  request_headers = curl_slist_append (request_headers, "Content-Type: text/xml");
  request_headers = curl_slist_append (request_headers, "Depth: 0");
  curl_easy_setopt (c->handle, CURLOPT_HTTPHEADER, request_headers);
  curl_easy_setopt (c->handle, CURLOPT_CUSTOMREQUEST, "PROPFIND");

  /* Perform Request */
  res = curl_easy_perform (c->handle);

  /* Free Resources */
  curl_easy_reset (c->handle);
  curl_slist_free_all (request_headers);
  free (url);

  /* Check for Curl Errors */
  if (res != 0)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Response Code */
  if (curl_easy_getinfo (c->handle, CURLINFO_RESPONSE_CODE, &response_code))
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }
  if (response_code == 404)
    {
      free (curl_data.data);
      return CONNECTOR_DOESNT_EXIST;
    }
  if (response_code < 200 || response_code > 299)
    {
      free (curl_data.data);
      return CONNECTOR_UNKNOWN;
    }

  /* Check Response Type */
  response_type = NULL;
  if (curl_easy_getinfo (c->handle, CURLINFO_CONTENT_TYPE, &response_type) || response_type == NULL)
    {
      free (curl_data.data);
      return CONNECTOR_INVALID_TIMESTAMP;
    }
  if (strncmp (response_type, "application/xml", strlen ("application/xml")) && strncmp (response_type, "text/xml", strlen ("text/xml")))
    {
      free (curl_data.data);
      return CONNECTOR_INVALID_TIMESTAMP;
    }

  /* Parse XML Tree */
  xml_doc = xmlParseMemory (curl_data.data, curl_data.len);
  if (xml_doc == NULL)
    {
      free (curl_data.data);
      return CONNECTOR_INVALID_TIMESTAMP;
    }
  xml_root = xmlDocGetRootElement (xml_doc);
  xml_elem = connector_webdav_xml_get (xml_root, "getlastmodified");
  if (xml_elem == NULL)
    {
      xmlFreeDoc (xml_doc);
      free (curl_data.data);
      return CONNECTOR_INVALID_TIMESTAMP;
    }
  xml_str = xmlNodeListGetString (xml_doc, xml_elem->children, 1);
  xmlFreeDoc (xml_doc);
  free (curl_data.data);

  if (xml_str == NULL)
      return CONNECTOR_INVALID_TIMESTAMP;

  /* Convert Time to Valid Time */
  *time = connector_webdav_xml_to_time (xml_str);
  free (xml_str);

  /* Make sure time was valid */
  if (*time == 0)
    return CONNECTOR_INVALID_TIMESTAMP;

  return CONNECTOR_SUCCESS;
}

int
connector_webdav_acquire_lock (void * cdata, const unsigned char * obj)
{
  connector_webdav_t c;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  return CONNECTOR_UNKNOWN;
}

int
connector_webdav_release_lock (void * cdata, const unsigned char * obj)
{
  connector_webdav_t c;

  /* Get the connector variable */
  c = (connector_webdav_t)cdata;

  return CONNECTOR_UNKNOWN;
}

void
connector_webdav_disconnect (void * cdata)
{
  connector_webdav_t c;

  /* Get the connection variable */
  c = (connector_webdav_t)cdata;

  /* Free used connection memory */
  curl_easy_cleanup (c->handle);
  free (c->dir_url);
  if (c->user_pass)
    free (c->user_pass);
  free (cdata);
}
