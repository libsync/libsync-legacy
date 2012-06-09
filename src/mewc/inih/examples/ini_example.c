/* Example: parse a simple configuration file */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ini.h"

typedef struct
{
  int version;
  const char* name;
  const char* email;
  const char* url;
} configuration;

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
  configuration* pconfig = (configuration*)user;

#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0
  if (MATCH("protocol", "version")) {
    pconfig->version = atoi(value);
  } else if (MATCH("user", "name")) {
    pconfig->name = strdup(value);
  } else if (MATCH("user", "email")) {
    pconfig->email = strdup(value);
  } else if (MATCH("user", "url")) {
    pconfig->email = strdup(value);
  } else {
    return 0;  /* unknown section/name, error */
  }
  return 1;
}

int main(int argc, char* argv[])
{
  configuration config;

  if (ini_parse("test.ini", handler, &config) < 0) {
    printf("Can't load 'test.ini'\n");
    return 1;
  }
  printf("Config loaded from 'test.ini': version=%d, name=%s, email=%s\n",
	 config.version, config.name, config.email, config.url);
  return 0;
}