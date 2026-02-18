// ml_joblib_bridge.h
#pragma once
#include <stddef.h>

int  ml_joblib_init(const char *model_path);          // returns 1 on success
double ml_joblib_predict_proba1(const double *x, size_t n); // returns p(class=1)
void ml_joblib_shutdown(void);
