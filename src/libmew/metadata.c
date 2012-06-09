#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include "metadata.h"
#include "connector.h"
#include "crypto.h"

struct _metadata_t
{
  metadata_entry_t **table;
  size_t table_size, table_len;
  time_t last_date;
};

void
metadata_init (metadata_t * data)
{
  /* Initialize the data structure */
  *data = (metadata_t) malloc (sizeof (struct _metadata_t));
  (*data)->table_size = 16;
  (*data)->table = (metadata_entry_t **) malloc ( (*data)->table_size *
						  sizeof (metadata_entry_t *));
  (*data)->table_len = 0;
  (*data)->last_date = 0;
}

enum metadata_update
metadata_update_put (metadata_t data, connector_t conn, crypto_sym_t crypto)
{
  char *tmp_data, *tmp_str;
  time_t new_date;
  int ret;
  size_t tmp_size, tmp_len, tmp_pos, array_size;
  size_t i, len, amount, struct_size;
  ssize_t table_pos;
  unsigned long version, time;

  /* Initialize the data segment */
  tmp_len = 0;
  tmp_size = 2 * sizeof (unsigned long);
  tmp_data = (char *) malloc (tmp_size * sizeof (char));

  /* Setup Version Information */
  *((unsigned long *) tmp_data) = htonl(1);
  tmp_len = sizeof (unsigned long);

  /* Determine table size */
  array_size = 0;
  for (i = 0; i < data->table_len; i++)
    if (data->table[i]->filename != NULL)
      array_size++;
  *((unsigned long *) (tmp_data + tmp_len)) = htonl(array_size);
  tmp_len += sizeof (unsigned long);

  /* Encode each of the metadata entries */
  for (i = 0; i < data->table_len; i++)
    {
      if (data->table[i]->filename == NULL)
	continue;

      /* Calculate struct size */
      len = strlen (data->table[i]->filename) * sizeof (char);
      tmp_pos = len + sizeof (unsigned long) * 3 + sizeof (char) * 1;
      tmp_pos += 64 * sizeof (char);

      /* Make sure the tmp data is large enough */
      if (tmp_len + tmp_pos > tmp_size)
	{
	  while (tmp_len + tmp_pos > tmp_size) tmp_size <<= 1;
	  tmp_data = (char *) realloc (tmp_data, tmp_size);
	}

      /* Move the string into tmpdata */
      *((unsigned long *) (tmp_data + tmp_len)) = htonl (len);
      tmp_len += sizeof (unsigned long);
      memcpy(tmp_data + tmp_len, data->table[i]->filename, len);
      tmp_len += len;

      /* Move the rest of the struct */
      *((unsigned long *) (tmp_data + tmp_len)) = htonl (data->table[i]->timestamp);
      tmp_len += sizeof (unsigned long);
      *((unsigned long *) (tmp_data + tmp_len)) = htonl (data->table[i]->mark);
      tmp_len += sizeof (unsigned long);
      tmp_data[tmp_len++] = data->table[i]->deleted;

      /* Move the object name into tmpdata */
      memcpy (tmp_data + tmp_len, data->table[i]->objname, 64*sizeof (char));
      tmp_len += 64*sizeof (char);
    }

  /* Send the Data to the server */
  ret = connector_put (conn, "metadata", (void*)tmp_data, tmp_len, crypto);
  free (tmp_data);
  if (ret != CONNECTOR_SUCCESS)
    return METADATA_PUSH_FAILED;

  return METADATA_SUCCESS;
}

enum metadata_update
metadata_update_get (metadata_t data, connector_t conn, crypto_sym_t crypto)
{
  char *tmp_data, *tmp_str;
  time_t new_date;
  int ret;
  size_t tmp_size, tmp_len, tmp_pos, array_size;
  size_t i, len, amount, struct_size;
  ssize_t table_pos;
  unsigned long version, time;

  /* Get the Update Time */
  ret = connector_get_timestamp (conn, "metadata", &new_date);
  if (ret != CONNECTOR_DOESNT_EXIST && ret != CONNECTOR_SUCCESS)
    return METADATA_DOWNLOAD_FAILED;

  /* Retrieve Updated Metadata */
  tmp_data = NULL;
  tmp_size = 0;
  tmp_len = 0;
  if (ret == CONNECTOR_SUCCESS && new_date != data->last_date)
    {
      ret = connector_get (conn, "metadata",
			   (void **)&tmp_data, &tmp_size, &tmp_len,
			   crypto);
      if (ret != CONNECTOR_DOESNT_EXIST && ret != CONNECTOR_SUCCESS)
	return METADATA_DOWNLOAD_FAILED;
    }

  /* Clear Updated Flags */
  for (i = 0; i < data->table_len; i++)
    data->table[i]->updated = 0;

  /* Parse Updated Binary */
  if (ret == CONNECTOR_SUCCESS && new_date != data->last_date)
    {
      /* Update the Structure Date */
      data->last_date = new_date;

      /* Check Version */
      if (tmp_len < sizeof (unsigned long))
	{
	  free (tmp_data);
	  return METADATA_INVALID;
	}
      version = ntohl (*((unsigned long *) tmp_data));
      if (version > 1 || version == 0)
	{
	  free (tmp_data);
	  return METADATA_INVALID_VERSION;
	}

      tmp_pos = sizeof (unsigned long);

      /* Version 1 Check */
      if (version == 1)
	{
	  /* Get the amount of entries */
	  if (tmp_len < tmp_pos || tmp_len - tmp_pos < sizeof (unsigned long))
	    {
	      free (tmp_data);
	      return METADATA_INVALID;
	    }
	  amount = ntohl(*((unsigned long *) (tmp_data + tmp_pos)));
	  tmp_pos += sizeof (unsigned long);

	  /* Iterate over all data */
	  for (i = 0; i < amount; i++)
	    {
	      /* Get the length of the string */
	      if (tmp_len < tmp_pos || tmp_len - tmp_pos < sizeof (unsigned long))
		{
		  free (tmp_data);
		  return METADATA_INVALID;
		}
	      len = ntohl(*((unsigned long *) (tmp_data + tmp_pos)));
	      tmp_pos += sizeof (unsigned long);

	      /* Determine if we have enough stored data */
	      struct_size = len * sizeof (char);
	      struct_size += 2 * sizeof (unsigned long);
	      struct_size += 1 * sizeof (char);
	      struct_size += 64 * sizeof (char);
	      if (tmp_len < tmp_pos || tmp_len - tmp_pos < struct_size)
		{
		  free (tmp_data);
		  return METADATA_INVALID;
		}

	      /* Retrieve the string */
	      tmp_str = (char *) malloc ((len+1) * sizeof (char));
	      memcpy (tmp_str, tmp_data + tmp_pos, len);
	      tmp_str[len] = 0;
	      tmp_pos += len * sizeof (char);

	      /* See if the entry already exists */
	      table_pos = metadata_get_index (data, tmp_str);

	      /* Add a new entry */
	      if (table_pos == -1)
		{
		  /* Make sure we have enough table data */
		  if (data->table_len >= data->table_size)
		    {
		      data->table_size <<= 1;
		      data->table = (metadata_entry_t **)
			realloc (data->table,
				 data->table_size *
				 sizeof (metadata_entry_t *));
		    }
		  table_pos = data->table_len++;
		  data->table[table_pos] = (metadata_entry_t *)
		    malloc (sizeof (metadata_entry_t));
		  data->table[table_pos]->timestamp = 0;
		  data->table[table_pos]->filename = tmp_str;
		}
	      else
		free (tmp_str);

	      /* Update the entry if the timestamp is correct */
	      time = ntohl (*((unsigned long *)(tmp_data + tmp_pos)));
	      tmp_pos += sizeof (unsigned long);
	      if (data->table[table_pos]->timestamp < time)
		{
		  data->table[table_pos]->timestamp = time;

		  /* Set the mark */
		  data->table[table_pos]->mark = ntohl (*((unsigned long *)(tmp_data + tmp_pos)));

		  /* Set boolean chars */
		  data->table[table_pos]->deleted = tmp_data[tmp_pos+sizeof(unsigned long)];
		  data->table[table_pos]->updated = 1;

		  /* Copy Object Name */
		  memcpy (data->table[table_pos]->objname,
			  tmp_data+tmp_pos+sizeof (unsigned long)+sizeof (char),
			  64 * sizeof (char));
		  data->table[table_pos]->objname[64] = 0;
		}
	      else if (data->table[table_pos]->timestamp > time)
		data->table[table_pos]->updated = 2;
	      tmp_pos += sizeof(unsigned long) + sizeof (char) + 64 * sizeof (char);
	      data->table[table_pos]->updated |= 4;
	    }
	}
    }

  /* Check to see if we have new files */
  for (i = 0; i < data->table_len; i++)
    if (data->table[i]->updated == 0)
      data->table[i]->updated = 2;

  /* Free Temporary Data */
  if (tmp_data != NULL)
    free (tmp_data);

  return METADATA_SUCCESS;
}

enum metadata_update
metadata_wait_update (metadata_t data, connector_t conn,
		      crypto_sym_t crypto)
{
  return metadata_update_get (data, conn, crypto);
}

ssize_t
metadata_get_index (metadata_t data, const char * filename)
{
  size_t i;
  
  /* Compare each index to see if it matches */
  for (i = 0; i < data->table_len; i++)
    if (filename != NULL && strcmp (data->table[i]->filename, filename) == 0)
      return i;

  return -1;
}

metadata_entry_t *
metadata_get_entry (metadata_t data, size_t index)
{  
  return data->table[index];
}

metadata_entry_t *
metadata_insert (metadata_t data)
{
  metadata_entry_t *entry;

  /* Make sure we have enough room for the new entry */
  if (data->table_len >= data->table_size)
    {
      data->table_size <<= 1;
      data->table = (metadata_entry_t **) realloc (data->table, data->table_size *
						   sizeof (metadata_entry_t *));
    }

  /* Initialize New Entry */
  entry = (metadata_entry_t *) malloc (sizeof (metadata_entry_t));
  entry->filename = NULL;
  entry->mark = 0;
  entry->updated = 0;
  entry->deleted = 0;
  entry->timestamp = 0;

  /* Add Entry to the Table */
  data->table[data->table_len++] = entry;

  return entry;
}

size_t
metadata_len (metadata_t data)
{
  return data->table_len;
}

void
metadata_destroy (metadata_t data)
{
  size_t i;

  /* Iterate over the array freeing each entry */
  for (i = 0; i < data->table_len; i++)
    {
      if (data->table[i]->filename != NULL)
	free (data->table[i]->filename);
      free (data->table[i]);
    }

  /* Free the initial data structure */
  free (data->table);
  free (data);
}

void
metadata_print (metadata_t data)
{
  size_t i;
  metadata_entry_t* entry;
  
  /* Iterate over the array printing each entry */
  for (i = 0; i < data->table_len; i++)
    {
      entry = data->table[i];
      if (entry->filename != NULL)
	{
	  printf ("Filename: %s\n", entry->filename);
	  printf ("Timestamp: %ul\n", entry->timestamp);
	  printf ("Mark: %ul\n", entry->mark);
	  printf ("Updated: %d\n", entry->updated);
	  printf ("Deleted: %d\n", entry->deleted);
	  printf ("--------------------------------------------------\n");
	}
    }
}

int
metadata_object_name (metadata_entry_t * entry, char * filename)
{
  unsigned char hash[32], buffer[2048], *ret;
  EVP_MD_CTX md;
  FILE *file;
  int size;

  /* Attempt to open the directory */
  file = fopen (filename, "rb");
  if (file == NULL)
    return -1;

  /* Initialize Hash Context */
  EVP_MD_CTX_init (&md);
  EVP_DigestInit_ex (&md, EVP_sha256(), NULL);

  /* Read and Hash the File */
  while((size = fread (buffer, sizeof (char), 2048, file)) > 0)
    EVP_DigestUpdate (&md, buffer, size);

  /* Generate and report hash */
  EVP_DigestFinal_ex (&md, hash, &size);
  EVP_MD_CTX_cleanup (&md);
  ret = crypto_bytes_to_hex (hash, size);
  memcpy (entry->objname, ret, strlen(ret) + 1);
  free (ret);
  return 0;
}
