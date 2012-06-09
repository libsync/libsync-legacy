/**
   DONE Task1
   DONE Task2
   DONE Task3
   DONE Task4
   TODO Clean up memory
   TODO Clean up code
   TODO Comment
 */


#include <config.h>
#include <ftw.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include "../libmew/connector.h"
#include "../libmew/metadata.h"
#include "../libmew/crypto.h"
#include "inih/ini.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <linux/inotify.h>


#define DEFAULT_PORT "8888"  // the port users will be connecting to
#define BACKLOG 10	 // how many pending connections queue will hold
#define BUFFER 100000

typedef struct
{
  int version;
  const char* name;
  const char* email;
  const char* url;
  const char* type;
} configuration;

void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);
int lock_on_port(int* sock_fd);
void reap_zombies();
void* handle_connections(void* t);
struct addrinfo * try_to_bind( struct addrinfo *servinfo,
			       int yes, int* sock_fd);
void get_ip(struct sockaddr_storage *their_addr);
void* serve_client(void * t);
void send_data( int* new_fd, char* data, unsigned len);
int get_data(int* new_fd, char* buf, char** data, unsigned *len);
char* process_http_header_request(const char *request);
int process_request(int* new_fd, char* data, char** lines);
int compare_extension(char *filename, char *extension);
char* load_file(FILE * pFile, long *len);
char* get_content_type(char* file);
inline void tokenize(char** args,char* line);
void sigquit_handler(int sig_num);
int load_meta(const char *name, const struct stat *status, int type);
static int handler(void* user, const char* section, const char* name,
                   const char* value);
int IPC();
void load(int argc, char** argv);
void set_up_inotify();
void sync_all (connector_t conn, metadata_t meta, crypto_sym_t crypto);

typedef struct {
  int* new_fd;
} send_t;

metadata_t meta;
configuration config;
char* PORT;
connector_t c;
int* main_socket = NULL;
int exit_flag = 1;
crypto_sym_t crypt;

int
init_config(configuration* config)
{
  if (config == NULL)
    return -1;
  config->name = "";
  config->email = "";
  config->url = "";
  config->type = "";
}

int
main(int argc, char **argv)
{
  int sock_fd, rv;
  signal(SIGQUIT, sigquit_handler);
  signal(SIGPIPE, SIG_IGN);

  crypto_sym_init (&crypt, "mykey", strlen("mykey"), 1);
  connector_global_init ("webdav");
  if (connector_init (&c, "webdav"))
    {
      printf ("Failed to initialize webdav connector.\n");
      return EXIT_FAILURE;
    }
  printf ("Connect: %d\n", connector_connect(c, "https://www.box.net/dav/", "random@courseguide.info", "Uv6$3UnNF4r3znveWx*YDr87CRxfnzp#"));
  /* Check for global configuration changes and update accordingly */  
  load(argc, argv);   // Load file system metadata

  if(argc > 1)
    PORT = argv[1];
  else
    PORT = DEFAULT_PORT;
    
  rv =lock_on_port(&sock_fd);
  if (rv != 0)
    return rv;
  
  reap_zombies();
  pthread_t thread;
  pthread_create(&thread, NULL,handle_connections,(void*) &sock_fd);

  /*
    inotify setup
   */

  set_up_inotify();
  
  pthread_join(thread,NULL);
  
  connector_disconnect (c);
  connector_destroy (c);
  connector_global_cleanup ("webdav");

  return 0;
}

void
process_command(char** args, int* sd)
{
  // Add file
  if (strcasecmp(args[0],"put") == 0)
    {
      printf("got a put\n");
    }
    
  // Push file
  else if (strcasecmp(args[0],"get") == 0)
    printf("got a get\n");
  // Do a Sync_All
  else if (strcasecmp(args[0],"sync") == 0)
    {
      sync_all(c, meta, crypt);
      metadata_print(meta);
      printf("got a sync\n");
      char temp[1000];
      getcwd(temp,1000);
      send_data(sd, temp, strlen(temp));
    }
    
}

/*************************************************************************
                         Server Setup  Logic
 *************************************************************************/

/**
   Locks on the port
 */
int
lock_on_port(int *sock_fd)
{
  int rv;
  struct addrinfo hints, *servinfo, *p;
  int yes = 1;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  if (try_to_bind(servinfo,yes, sock_fd) == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    return 2;
  }

  freeaddrinfo(servinfo); // all done with this structure

  if (listen(*sock_fd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }  
  return 0;
}

/**
   
 */
struct addrinfo *
try_to_bind( struct addrinfo *servinfo,
	     int yes, int* sock_fd)
{
  struct addrinfo *p;
  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    // Get Socket canindate
    if ((*sock_fd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }
    
    // Set up socket
    if (setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
		   sizeof(int)) == -1) {
      perror("setsockopt");
      exit(1);
    }
    
    // Try to bind
    if (bind(*sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sock_fd);
      perror("server: bind");
      continue;
    }
    break;
  }
  return p;
}

/*************************************************************************
                         Server/Client Logic
 *************************************************************************/

/**
   
 */
void
get_client_fd(int *sock_fd, int *new_fd, struct sockaddr_storage* their_addr)
{
  //printf("getting client\n");
  socklen_t sin_size;
  *new_fd = -1;
  while (*new_fd == -1 && exit_flag) {
    // Spawn thread to handle new client
    sin_size = sizeof(their_addr);
    *new_fd = accept(*sock_fd, (struct sockaddr *)their_addr, &sin_size);
    if (*new_fd == -1) 
      perror("accept");
  }
  //printf("got client\n");
}

/**
   
 */
void*
handle_connections(void *t)
{
  int* sock_fd = (int*) t;
  main_socket = sock_fd;
  struct sockaddr_storage their_addr; // connector's address information
  int *new_fd;  // listen on sock_fd, new connection on new_fd
  //printf("server: waiting for connections...\n");
  pthread_t* thread;
  while(exit_flag) {  // main accept() loop
    new_fd = malloc(sizeof(int));
    get_client_fd(sock_fd, new_fd, &their_addr);
    //printf("added\n");
    thread = malloc(sizeof(pthread_t));
    pthread_create(thread, NULL,serve_client,(void*) new_fd);
  }
  pthread_join(*thread,NULL);
  pthread_exit(0);
}


/**
   
 */
void
send_back_http(int response_code, char* content_type, FILE * pFile, int* new_fd, char* keep_alive)
{
  char* s = "sdad";
  send_data(new_fd, s, strlen(s));
}

void
prepend(char* s, const char* t)
{
  size_t len = strlen(t);
  size_t i;

  memmove(s+len, s, len + 1);

  for (i = 0; i < len; i++)
    s[i] = t[i];
}


void*
serve_client(void* t)
{
  printf("----------Open----------\n");
  int* new_fd = (int*) t;
  char buf[BUFFER+1];
  char* data;
  unsigned len , flag=1;
  while (flag) {
    flag = get_data(new_fd, buf, &data, &len);
    if (!flag)
      break;
    if(len == 0)
      break;
    char **lines = malloc(100*sizeof(char*));
    tokenize(lines,data);
    process_command(lines, new_fd);
    send_data(new_fd, lines[0], strlen(lines[0]));
    free(lines);
    free(data);
  }
  printf("----------Closing----------\n");
  close(*new_fd);
  free(new_fd);
  pthread_exit(0);
}

/*************************************************************************
                           Helper Fuctions
 *************************************************************************/

/**
   
 */
void
send_data(int* new_fd, char* data, unsigned len)
{
  printf("sending\n");
  int bits_sent;
  while (len > 0) {
    bits_sent = send(*new_fd, data, len, 0);
    if (bits_sent == -1)
      perror("send");
    else {
      len -= bits_sent;
      data += bits_sent;
    }
  }
  printf("done sending\n");
}

/**
   
 */
int
get_data(int* new_fd, char* buf, char** data, unsigned *len)
{
  unsigned bytes_recv;
  char* temp;
  temp = malloc(BUFFER*sizeof(char));  // set up a new string for the data
  temp[0] = '\0';
  *len = 0; // set initial len
  // ask for data
  if(!exit_flag){
    free(temp);
    return 0;
  }
  while ((bytes_recv = recv(*new_fd, buf, BUFFER, 0)) > 0) {
    printf("got it\n");
    if(!exit_flag){
      free(temp);
      return 0;
    }

    if (bytes_recv == 0){
      printf("here\n");
      exit(0);
      return 0; // TODO CLEANUP
    }
    

    buf[bytes_recv+1] = '\0'; // make sure its null terminated
    strcat(temp, buf);
    if (strstr(temp,"\\r\\n\\r\\n") != NULL)
      {
	strstr(temp,"\\r\\n\\r\\n")[0] = '\0';
	break;
      }
    if(strstr(temp,"\r\n\r\n") != NULL)
      {
	strstr(temp,"\r\n\r\n")[0] = '\0';
	break;
      }

  }
  *len = strlen(temp);
  *data = temp;
  //printf("ugh\n");
  //  process_command(lines);

  if(!exit_flag){
    free(temp);
    return 0;
  }

  return 1;
}

/**
   
 */
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
    return &(((struct sockaddr_in*)sa)->sin_addr);
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
   
 */
void get_ip(struct sockaddr_storage *their_addr)
{
  char s[INET6_ADDRSTRLEN];
  inet_ntop(their_addr->ss_family,
	    get_in_addr((struct sockaddr *)their_addr),
	    s, sizeof s);
  printf("server: got connection from %s\n", s);
}

/**
   
 */
void
reap_zombies()
{
  struct sigaction sa;
  sa.sa_handler = sigchld_handler; // reap all dead processes
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }
}

/**
   
 */
int compare_extension(char *filename, char *extension)
{
  /* Sanity checks */

  if(filename == NULL || extension == NULL)
    return 0;

  if(strlen(filename) == 0 || strlen(extension) == 0)
    return 0;

  if(strchr(filename, '.') == NULL || strchr(extension, '.') == NULL)
    return 0;

  /* Iterate backwards through respective strings and compare each char one at a time */
  unsigned i;
  for( i = 0; i < strlen(filename); i++)
    {
      if(filename[strlen(filename) - i - 1] == extension[strlen(extension) - i - 1])
	{
	  if(i == strlen(extension) - 1)
	    return 1;
	} else
	break;
    }

  return 0;
}



/**
   
 */
void
sigchld_handler(int s)
{
  while(waitpid(-1, NULL, WNOHANG) > 0);
}

void
sigquit_handler(int sig_num)
{
  exit(0);
}

/**
 * Processes the request line of the HTTP header.
 * 
 * @param request The request line of the HTTP header.  This should be
 *                the first line of an HTTP request header and must
 *                NOT include the HTTP line terminator ("\r\n").
 *
 * @return The filename of the requested document or NULL if the
 *         request is not supported by the server.  If a filename
 *         is returned, the string must be free'd by a call to free().
 */

/**
   
 */
inline void
tokenize(char** args,char* line)
{
  char* command;
  int size;
  command = strtok(line, " ");
  for(size = 0; command; size++) {
    args[size] = command;
    command = strtok(NULL, " ");
  }
  args[size] = NULL;
}

/**
   
 */
char*
get_content_type(char* file)
{
  if(compare_extension(file, ".html"))
    return "text/html";
  if(compare_extension(file, ".css"))
    return "text/css";
  if(compare_extension(file, ".jpeg"))
    return "image/jpg";
  if(compare_extension(file, ".png"))
    return "image/png";
  return "text/plain";
}

int
parse_config()
{
  init_config(&config);
  if (ini_parse("test.ini", handler, &config) < 0) {
    printf("Can't load 'test.ini'\n");
    return 1;
  }
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
  configuration* pconfig = (configuration*)user;

#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0
  if (MATCH("protocol", "version")) {
    pconfig->version = atoi(value);
  } else if (MATCH("protocol", "type")) {
    pconfig->type = strdup(value);
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


void
load(int argc, char** argv)
{
  metadata_init (&meta);
  if(argc == 1)
    ftw64(".", load_meta, 1); // just use 1 FD...if to many dirs bump up to larger number
  else
    ftw64(argv[1], load_meta, 1);
  //metadata_print(meta);
}

/**
   Examines given directory and adds all files in the directory to the metadata stucture.
*/

int
load_meta(const char *name, const struct stat *status, int type) {
  metadata_entry_t *entry;
  char* filename;
  //  struct _metadata_t* meta;
  if(type == FTW_NS)
    return 0;

  if(type == FTW_F){
    entry = metadata_insert (meta);
    entry->filename = strdup(name);
    entry->timestamp = status->st_mtime;
  }
  return 0;
}


/*************************************************************************
                           Inotify code
 *************************************************************************/

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define BUFF 100
/**
   Examines given directory and adds all files in the directory to the metadata stucture.
*/

int fd;
int array[BUFF];
int count;

int
load_notify(const char *name, const struct stat *status, int type) {
  char* filename;
  int wd;
  //  struct _metadata_t* meta;
  if(type == FTW_NS)
    return 0;
  if(type == FTW_D && strcmp(".", name) != 0 && strcmp("..", name) != 0)
    {
      printf("added %s\n", name);
      wd = inotify_add_watch( fd, name, IN_CREATE | IN_DELETE | IN_MODIFY );
      array[wd] = wd;
      count ++;
    }    
  return 0;
}

void
set_up_inotify()
{
  int length, i = 0;
  int wd;
  char buffer[EVENT_BUF_LEN];
  count = 0;
  /*creating the INOTIFY instance*/
  fd = inotify_init();
  ftw64(".", load_notify, 1); // just use 1 FD...if to many dirs bump up to larger number
  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  /*add in the “/tmp” directory into watch list. Here, the suggestion is to validate the existence of the directory before adding into monitoring list.*/
  wd = inotify_add_watch( fd, ".", IN_CREATE | IN_DELETE | IN_MODIFY );

  /*read to determine the event change happens on “/tmp” directory. Actually this read blocks until the change event occurs*/ 



  /*checking for error*/
  if ( length < 0 ) {
    perror( "read" );
  }  

  while(1){
    i = 0;
    length = read( fd, buffer, EVENT_BUF_LEN ); 
    /*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
    while ( i < length ) {
      struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];
      if ( event->len ) {
	if ( (event->mask & IN_CREATE) || (event->mask & IN_MODIFY) ) {
	  if ( event->mask & IN_ISDIR ) {
	    printf( "New directory %s created.\n", event->name );
	    
	  }
	  else {
	    printf( "New file %s created.\n", event->name );
	    ssize_t j = metadata_get_index(meta, event->name);
	    metadata_entry_t *entry;
	    if (j >= 0)
	      {
		entry = metadata_get_entry(meta, j);
		entry->deleted = 0;
	      }
	    else
	      {
		entry = metadata_insert (meta);
		entry->filename = strdup(event->name);
	      }
	    struct stat fileStat;
	    if(stat(event->name,&fileStat) < 0)    
	      continue;
	    entry->timestamp = fileStat.st_mtime;
	  }
	}
	else if ( event->mask & IN_DELETE ) {
	  if ( event->mask & IN_ISDIR ) {
	    printf( "Directory %s deleted.\n", event->name );
	  }
	  else {
	    size_t j = metadata_get_index(meta, event->name);
	    if (j<0)
	      continue;
	    metadata_entry_t *entry = metadata_get_entry(meta, j);
	    entry->deleted = 1;
	    entry->timestamp = time(NULL);
	    printf( "File %s deleted.\n", event->name );
	  }
	}
      }
      i += EVENT_SIZE + event->len;
    }
    printf("about to sync\n");
    sync_all(c, meta, crypt);
  }
  /*removing the “/tmp” directory from the watch list.*/
  for (i=0;i<count;i++)
    inotify_rm_watch( fd, array[i] );
  inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
  close( fd );
}

void
sync_all (connector_t conn, metadata_t meta, crypto_sym_t crypto)
{
  size_t i, size;
  metadata_entry_t *entry;

  /* Pull the metadata */
  metadata_update_get (meta, conn, crypto);

  /* Iterate over each metadata entry which needs syncing */
  size = metadata_len (meta);
  printf ("%d\n", size);
  for (i = 0; i < size; i++)
    {
      entry = metadata_get_entry (meta, i);
      printf ("Name: %s\n", entry->filename);
      /* Push Data */
      if ((entry->updated & 0x2) != 0 && entry->deleted == 0)
	{
	  metadata_object_name (entry, entry->filename);
	  printf ("ObjName: %s\n", entry->objname);
	  connector_put_file (conn, entry->objname, entry->filename, crypto);
	}
      /* Pull Data */
      else if ((entry->updated & 0x1) != 0)
	if (entry->deleted == 0)
	  connector_get_file (conn, entry->objname, entry->filename, crypto);
	else
	  unlink (entry->filename);
    }

  /* Push the new metadata */
  metadata_update_put (meta, conn, crypto);
}
