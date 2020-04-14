#ifndef ENCLAVE_SERIALISE_H
#define ENCLAVE_SERIALISE_H

#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>


typedef struct {
  int *array;
  size_t used;
  size_t size;
} i_Array;

typedef struct {
  unsigned char *array;
  size_t used;
  size_t size;
} uc_Array;

void init_i_Array(i_Array *a, size_t initialSize);
void insert_i_Array(i_Array *a, int element);
void free_i_Array(i_Array *a);

void init_uc_Array(uc_Array *a, size_t initialSize);
void insert_uc_Array(uc_Array *a, unsigned char * element, size_t len);
void free_uc_Array(uc_Array *a);


#endif