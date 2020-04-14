#include "Serialise.h"

//for int array
void init_i_Array(i_Array *a, size_t initialSize){
    a->array = (int *)malloc(initialSize * sizeof(int));
    a->used = 0;
    a->size = initialSize;
}

void insert_i_Array(i_Array *a, int element){

    if (a->used == a->size) {
        a->size *= 2; //double size
        a->array = (int *)realloc(a->array, a->size * sizeof(int));
    }

    a->array[a->used++] = element;
}

void free_i_Array(i_Array *a){
    free(a->array);
    a->array = NULL;
    a->used = a->size = 0;
}

//for unsigned char array
void init_uc_Array(uc_Array *a, size_t initialSize){
    a->array = (unsigned char *)malloc(initialSize * sizeof(unsigned char));
    a->used = 0;
    a->size = initialSize;
}

void insert_uc_Array(uc_Array *a, unsigned char * element, size_t len){
    if (a->used == a->size) {
        a->size *= 2; //double size
        a->array = (unsigned char *)realloc(a->array, a->size * sizeof(unsigned char));
    }

    memcpy(a+a->used,element,len);
    a->used += len;
}

void free_uc_Array(uc_Array *a){
    free(a->array);
    a->array = NULL;
    a->used = a->size = 0;
}
