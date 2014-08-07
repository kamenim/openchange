/*
   OpenChange MAPI implementation.

   Python interface to mapistore

   Copyright (C) Julien Kerihuel 2010-2011.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include "pyopenchange/mapistore/pymapistore.h"
#include "pyopenchange/pymapi.h"

#include <param.h>
#include <samba/session.h>

/* static PyTypeObject *SPropValue_Type; */
PyAPI_DATA(PyTypeObject)	PyMAPIStoreDirect;

void initmapistore_direct(PyObject *module);

void sam_ldb_init(const char *syspath);

void openchange_ldb_init(const char *syspath);

static void PyErr_SetMAPISTATUSError(enum MAPISTATUS retval)
{
	PyErr_SetObject(PyExc_RuntimeError,
			Py_BuildValue("(i, s)", retval, mapi_get_errstr(retval)));
}

static PyObject *py_MAPIStoreDirect_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX			*mem_ctx;
	PyMAPIStoreGlobals		*globals;
	struct loadparm_context		*lp_ctx;
	struct mapistore_context	*mstore_ctx;
	PyMAPIStoreObject		*msdobj;
	char				*kwnames[] = { "syspath", "path", NULL };
	const char			*path = NULL;
	const char			*syspath = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|ss", kwnames, &syspath, &path)) {
		return NULL;
	}

	globals = get_PyMAPIStoreGlobals();

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	/* Initialize configuration */
	lp_ctx = loadparm_init(mem_ctx);
	lpcfg_load_default(lp_ctx);

	if (syspath == NULL) {
		syspath = lpcfg_private_dir(lp_ctx);
	}

	/* Initialize ldb context on sam.ldb */
	sam_ldb_init(syspath);
	if (globals->samdb_ctx == NULL) {
		PyErr_SetString(PyExc_SystemError,
				"error in sam_ldb_init");
		talloc_free(mem_ctx);
		return NULL;
	}

	/* Initialize ldb context on openchange.ldb */
	openchange_ldb_init(syspath);
	if (globals->ocdb_ctx == NULL) {
		PyErr_SetString(PyExc_SystemError,
				"Failed to open openchange.ldb");
		talloc_free(mem_ctx);
		return NULL;
	}

	/* Initialize mapistore */
	mstore_ctx = mapistore_init(mem_ctx, lp_ctx, path);
	if (mstore_ctx == NULL) {
		PyErr_SetString(PyExc_SystemError,
				"error in mapistore_init");
		talloc_free(mem_ctx);
		return NULL;
	}

	msdobj = PyObject_New(PyMAPIStoreObject, &PyMAPIStoreDirect);
	msdobj->mem_ctx = mem_ctx;
	msdobj->mstore_ctx = mstore_ctx;

	return (PyObject *) msdobj;
}

static void py_MAPIStoreDirect_dealloc(PyObject *_self)
{
	PyMAPIStoreObject *self = (PyMAPIStoreObject *)_self;

	mapistore_release(self->mstore_ctx);
	talloc_free(self->mem_ctx);
	PyObject_Del(_self);
}

static PyObject *py_MAPIStoreDirect_list_contexts_for_user(PyMAPIStoreObject *self, PyObject *args, PyObject *kwargs)
{
	TALLOC_CTX 			*mem_ctx;
	enum mapistore_error		retval;
	PyObject			*py_dict;
	PyObject 			*py_ret = NULL;
	const char			*username;
	char				*kwnames[] = { "username", NULL };
	struct mapistore_contexts_list 	*contexts_list;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s", kwnames, &username)) {
		return NULL;
	}

	DEBUG(0, ("List contexts for user: %s\n", username));

	mem_ctx = talloc_new(NULL);

	/* list contexts */
	retval = mapistore_list_contexts_for_user(self->mstore_ctx, username, mem_ctx, &contexts_list);
	if (retval != MAPISTORE_SUCCESS) {
		goto end;
	}

	py_ret = Py_BuildValue("[]");

	while (contexts_list) {
		py_dict = Py_BuildValue("{s:s, s:s, s:i, s:i}",
				"name", contexts_list->name,
				"url", contexts_list->url,
				"role", contexts_list->role,
				"main_folder", contexts_list->main_folder);
		PyList_Append(py_ret, py_dict);
		contexts_list = contexts_list->next;
	}

end:
	TALLOC_FREE(mem_ctx);
	return (PyObject *) py_ret;
}

static PyObject *py_MAPIStoreDirect_add_context(PyMAPIStoreObject *self, PyObject *args, PyObject *kwargs)
{
	enum mapistore_error		ret;
	enum MAPISTATUS			retval;
	PyMAPIStoreContextObject	*context;
	uint32_t			context_id = 0;
	char				*kwnames[] = { "uri", "username", NULL };
	const char			*uri;
	const char			*username;
	void				*folder_object;
        uint64_t			fid = 0;
	PyMAPIStoreGlobals		*globals;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ss", kwnames, &uri, &username)) {
		return NULL;
	}

	globals = get_PyMAPIStoreGlobals();

	/* Initialize connection info */
	ret = mapistore_set_connection_info(self->mstore_ctx, globals->samdb_ctx, globals->ocdb_ctx, username);
	if (ret != MAPISTORE_SUCCESS) {
		PyErr_SetMAPIStoreError(ret);
		return NULL;
	}

	/* Get FID given mapistore_uri and username */
	retval = openchangedb_get_fid(globals->ocdb_ctx, uri, &fid);
	if (MAPI_STATUS_IS_ERR(retval)) {
		PyErr_SetMAPISTATUSError(ret);
		return NULL;
	}

	ret = mapistore_add_context(self->mstore_ctx, username, uri, fid, &context_id, &folder_object);
	if (ret != MAPISTORE_SUCCESS) {
		PyErr_SetMAPIStoreError(ret);
		return NULL;
	}

	context = PyObject_New(PyMAPIStoreContextObject, &PyMAPIStoreContext);
	context->mem_ctx = self->mem_ctx;
	context->mstore_ctx = self->mstore_ctx;
	context->fid = fid;
	context->folder_object = folder_object;
	context->context_id = context_id;
	context->parent = self;

	Py_INCREF(context->parent);

	return (PyObject *) context;
}

static PyObject *py_MAPIStoreDirect_del_context(PyMAPIStoreObject *self, PyObject *args, PyObject *kwargs)
{
	enum mapistore_error		ret;
	PyMAPIStoreContextObject	*context;
	char				*kwnames[] = { "context", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O!", kwnames, &PyMAPIStoreContext, &context)) {
		return NULL;
	}

//	ret = mapistore_del_context(self->mstore_ctx, context->context_id);
//	Py_XDECREF(context);
//	if (ret != MAPISTORE_SUCCESS) {
//		PyErr_SetMAPIStoreError(ret);
//		return Py_False;
//	}

	Py_RETURN_TRUE;
}

static PyMethodDef mapistore_direct_methods[] = {
	{ "list_contexts_for_user", (PyCFunction)py_MAPIStoreDirect_list_contexts_for_user, METH_VARARGS|METH_KEYWORDS },
	{ "add_context", (PyCFunction)py_MAPIStoreDirect_add_context, METH_VARARGS|METH_KEYWORDS },
//	{ "del_context", (PyCFunction)py_MAPIStoreDirect_del_context, METH_VARARGS|METH_KEYWORDS },
	{ NULL },
};

PyTypeObject PyMAPIStoreDirect = {
	PyObject_HEAD_INIT(NULL) 0,
	.tp_name = "mapistore.MAPIStoreDirect",
	.tp_basicsize = sizeof (PyMAPIStoreObject),
	.tp_doc = "Thin layer to access mapistore interface",
	.tp_methods = mapistore_direct_methods,
	/* .tp_getset = mapistore_getsetters, */
	.tp_new = py_MAPIStoreDirect_new,
	.tp_dealloc = (destructor)py_MAPIStoreDirect_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
};


void initmapistore_direct(PyObject *module)
{
	if (PyType_Ready(&PyMAPIStoreDirect) < 0) {
		return;
	}
	Py_INCREF(&PyMAPIStoreDirect);

	PyModule_AddObject(module, "MAPIStoreDirect", (PyObject *)&PyMAPIStoreDirect);
}
