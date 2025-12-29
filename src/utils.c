#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

char *alloc(char const* msg){
  int len;
  char *res;

  len = strlen(msg)+1;
  res = (char *) malloc(sizeof(char)*len);
  strncpy(res, msg, len); 

  return res;
}

char *intToStr(int x){
  int len;
  char *res=NULL;

  len = snprintf(res, 0, "%d", x)+1;
  res = (char *)malloc(len*sizeof(char));
  snprintf(res, len, "%d", x);

  return res;
}
