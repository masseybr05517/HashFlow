// ml_joblib_bridge.c
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdio.h>
#include <string.h>

#include "ml_joblib_bridge.h"

static int g_inited = 0;
static PyObject *g_mod = NULL;
static PyObject *g_init_fn = NULL;
static PyObject *g_pred_fn = NULL;

int ml_joblib_init(const char *model_path) {
  if (g_inited) return 1;

  Py_Initialize();
  if (!Py_IsInitialized()) {
    fprintf(stderr, "Python init failed\n");
    return 0;
  }

  // Ensure current directory is on sys.path so joblib_predict.py is importable
  PyRun_SimpleString("import sys; sys.path.insert(0, '')");

  g_mod = PyImport_ImportModule("joblib_predict");
  if (!g_mod) {
    PyErr_Print();
    fprintf(stderr, "Failed to import joblib_predict\n");
    return 0;
  }

  g_init_fn = PyObject_GetAttrString(g_mod, "init");
  g_pred_fn = PyObject_GetAttrString(g_mod, "predict_proba_1");
  if (!g_init_fn || !PyCallable_Check(g_init_fn) || !g_pred_fn || !PyCallable_Check(g_pred_fn)) {
    PyErr_Print();
    fprintf(stderr, "joblib_predict.init or predict_proba_1 missing/not callable\n");
    return 0;
  }

  // Call init(model_path, expected_n=27)
  PyObject *args = Py_BuildValue("(si)", model_path, 27);
  PyObject *ret = PyObject_CallObject(g_init_fn, args);
  Py_XDECREF(args);

  if (!ret) {
    PyErr_Print();
    fprintf(stderr, "joblib_predict.init() failed\n");
    return 0;
  }
  Py_DECREF(ret);

  g_inited = 1;
  return 1;
}

double ml_joblib_predict_proba1(const double *x, size_t n) {
  if (!g_inited || !g_pred_fn || !x || n == 0) return 1.0;

  // Build a Python list of floats
  PyObject *list = PyList_New((Py_ssize_t)n);
  if (!list) {
    PyErr_Print();
    return 1.0;
  }
  for (size_t i = 0; i < n; i++) {
    PyObject *v = PyFloat_FromDouble(x[i]);
    if (!v) {
      PyErr_Print();
      Py_DECREF(list);
      return 1.0;
    }
    PyList_SET_ITEM(list, (Py_ssize_t)i, v); // steals ref
  }

  PyObject *args = PyTuple_New(1);
  PyTuple_SET_ITEM(args, 0, list); // steals ref to list

  PyObject *ret = PyObject_CallObject(g_pred_fn, args);
  Py_DECREF(args);

  if (!ret) {
    PyErr_Print();
    return 1.0;
  }

  double p = PyFloat_AsDouble(ret);
  Py_DECREF(ret);

  if (PyErr_Occurred()) {
    PyErr_Print();
    return 1.0;
  }
  return p;
}

void ml_joblib_shutdown(void) {
  if (!g_inited) return;

  Py_XDECREF(g_pred_fn);
  Py_XDECREF(g_init_fn);
  Py_XDECREF(g_mod);

  Py_Finalize();
  g_pred_fn = g_init_fn = g_mod = NULL;
  g_inited = 0;
}
