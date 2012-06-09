#include <Python.h>
#include <structmember.h>
#include "connector.h"

/**
   TODO build global check for intialization and do that automagically
 */

typedef struct
{
  PyObject_HEAD
  connector_t c;
  const char* url;
  int connected;
} ConnectorObject;

static char connector_start_doc[] = "This is a global init\nRun once before using a connector";
static PyObject*
connector_start(PyObject *self, PyObject *args)
{
  const char *type;
  if (!PyArg_ParseTuple(args, "s:start", &type))
    return NULL;

  connector_global_init(type);
  return Py_None;
}


static char connector_end_doc[] = "This is a global clean up\nRun just once at the end of the program to clean up stuff";
static PyObject*
connector_end(PyObject *self, PyObject *args)
{
  const char *type;
  if (!PyArg_ParseTuple(args, "s:end", &type))
    return NULL;
  
  connector_global_cleanup(type);
  return Py_None;
}


static PyMethodDef connector_methods[] = {
  {"start", connector_start, METH_VARARGS, connector_start_doc},
  {"end", connector_end, METH_VARARGS, connector_end_doc},
  {NULL,NULL}
};

static char connector_doc[] = "Takes a protocal type as an argument: webdav, ftp,...\n Params: type\n returns Connector Object";
static int
Connector_init(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char *type;
  static char *kwlist[] = {"type", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist,
				   &type))
    return -1;
  // Set up data structure
  self->connected = 0;
  self->url = NULL;
  connector_init(&self->c, type);
  return 0;
}

static PyMemberDef Connector_members[] = {
  {NULL}
};

static char connector_connect_doc[] = "Connects to a server (assumes type matches initialized type\nParams: url, usr, password\nReturns 1 on success\nReturns 0 on failure)";
static PyObject*
Connector_connect(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char *url, *user, *password;
  static char *kwlist[] = {"url","user","password", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sss", kwlist,
				   &url, &user, &password))
    return NULL;

  self->url = url;
  self->connected = 1;
  connector_connect(self->c, url, user, password);
  return Py_BuildValue("i", 1);
}

static char connector_get_file_doc[] = "Gets a file from server and saves it as obj\nParams: obj,file_name\nReturns 1 on success)";
static PyObject *
Connector_get_file(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char *obj, *file;
  static char *kwlist[] = {"obj","file_name", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist,
				   &obj, &file))
    return NULL;

  if (self->connected == 0) // safety first
    return Py_BuildValue("i", 0);
  
  connector_get_file(self->c, obj, file);

  return Py_BuildValue("i", 1);
}

static char connector_put_file_doc[] = "Puts a file on server and saves it as obj\nParams: obj, file_name\nReturns 1 on success)";
static PyObject *
Connector_put_file(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char *obj, *file;
  static char *kwlist[] = {"obj","file_name", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "ss", kwlist,
				   &obj, &file))
    return NULL;

  if (self->connected == 0) // safety first
    return Py_BuildValue("i", 0);
  
  connector_put_file(self->c, obj, file);
  
  return Py_BuildValue("i", 1);
}

static PyObject *
Connector_get_timestamp(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char *obj;
  int time;
  static char *kwlist[] = {"obj","time", NULL};

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sl", kwlist,
				   &obj, &time))
    return NULL;
  
  //  connector_get_timestamp(self->c, obj, (time_t)time);
  
  return Py_None;
}

static PyObject *
Connector_acquire_lock(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char obj;
  static char *kwlist[] = {"obj","time", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sl", kwlist,
				   &obj, &time))
    return NULL;
  
  connector_acquire_lock(self->c,& obj);
  
  return Py_None;
}

static PyObject *
Connector_release_lock(ConnectorObject *self, PyObject *args, PyObject *kwds)
{
  const char obj;
  static char *kwlist[] = {"obj","time", NULL};
  if (!PyArg_ParseTupleAndKeywords(args, kwds, "sl", kwlist,
				   &obj, &time))
    return NULL;
  connector_release_lock(self->c, &obj);
  
  return Py_None;
}

static char connector_disconnect_doc[] = "Disconnects from current server\nParams:None\nReturns 1 on success)";
static PyObject *
Connector_disconnect(ConnectorObject *self, PyObject *args)
{
  if (self->connected == 1) // Check to make sure this makes sense
    return Py_BuildValue("i", 0);
  
  connector_disconnect(self->c);
  self->connected = 0;
  self->url = NULL;
  
  return Py_BuildValue("i", 1);
}

static PyMethodDef Connector_methods[] = {
  {"connect", (PyCFunction)Connector_connect, METH_KEYWORDS, connector_connect_doc},
  //{"get", (PyCFunction)Connector_get, METH_VARARGS, ""},
  //  {"put", (PyCFunction)Connector_put, METH_VARARGS, ""},
  {"get_file", (PyCFunction)Connector_get_file, METH_KEYWORDS, connector_get_file_doc},
  {"put_file", (PyCFunction)Connector_put_file, METH_KEYWORDS, connector_put_file_doc},
  {"get_timestamp", (PyCFunction)Connector_get_timestamp, METH_KEYWORDS, ""},
  {"acquire_lock", (PyCFunction)Connector_acquire_lock, METH_KEYWORDS, ""},
  {"release_lock", (PyCFunction)Connector_release_lock, METH_KEYWORDS, ""},
  {"disconnect", (PyCFunction)Connector_disconnect, METH_VARARGS, ""},
  {NULL}
};

int connector_print(PyObject* self, FILE* fp, int flags)
{
  ConnectorObject *object = (ConnectorObject *)self;
  if (object->connected == 0)
    fprintf(fp, "Currently not connected\n");
  else
    fprintf(fp, "Connected to %s\n", object->url);
  return 0;
}

static char Connector_doc[] = "This is the documentation.";

static PyTypeObject ConnectorObjectType = {
  PyObject_HEAD_INIT(NULL)
  0,/* ob_size           */
  "name.Connector",/* tp_name           */
  sizeof(ConnectorObject),/* tp_basicsize      */
  0,/* tp_itemsize       */
  0,/* tp_dealloc        */
  connector_print,/* tp_print          */
  0,/* tp_getattr        */
  0,/* tp_setattr        */
  0,/* tp_compare        */
  0,/* tp_repr           */
  0,/* tp_as_number      */
  0,/* tp_as_sequence    */
  0,/* tp_as_mapping     */
  0,/* tp_hash           */
  0,/* tp_call           */
  0,/* tp_str            */
  0,/* tp_getattro       */
  0,/* tp_setattro       */
  0,/* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,/* tp_flags          */
  Connector_doc,/* tp_doc            */
  0,/* tp_traverse       */
  0,/* tp_clear          */
  0,/* tp_richcompare    */
  0,/* tp_weaklistoffset */
  0,/* tp_iter           */
  0,/* tp_iternext       */
  Connector_methods,     /* tp_methods        */
  Connector_members,/* tp_members        */
  0,/* tp_getset         */
  0,/* tp_base           */
  0,/* tp_dict           */
  0,/* tp_descr_get      */
  0,/* tp_descr_set      */
  0,/* tp_dictoffset     */
  (initproc)Connector_init,/* tp_init           */
};

PyMODINIT_FUNC
initconnector(void)
{
  PyObject *m;

  ConnectorObjectType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&ConnectorObjectType)<0)
    return;

  m = Py_InitModule3("connector",connector_methods, connector_doc);

  if (m == NULL)
    return;

  Py_INCREF(&ConnectorObjectType);
  PyModule_AddObject(m, "Connector", (PyObject *)&ConnectorObjectType);
}
