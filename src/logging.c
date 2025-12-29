#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <main.h>

#include "logging.h"

typedef struct log_msg_t{
  int priority;
  char *buf;
} log_msg;

unsigned int accumulate = 0;
log_msg *msgs = NULL;

void dumpLog(){
  unsigned int i;

  switch(configServeur.logDest){
    case UNDEF:
    case STDERR:
      for(i=0; i<accumulate; i++)
        fprintf(stderr, "%s\n", msgs[i].buf);
      break;
    case SYSLOG:
      for(i=0; i<accumulate; i++)
        syslog(msgs[i].priority, "%s", msgs[i].buf);
      break;
    case BOTH:
      for(i=0; i<accumulate; i++){
        syslog(msgs[i].priority, "%s", msgs[i].buf);
        fprintf(stderr, "%s", msgs[i].buf);
      }
      break;
    default:
      fprintf(stderr, "Destination de journalisation inconnue: %d\n", configServeur.logDest);
      exit(-1);
  }
  
  for(i=0; i<accumulate; i++){
    free(msgs[i].buf);
    accumulate=0;
    free(msgs);
    msgs=NULL;
  }
}

void logging(int priority, const char *format, ...){
  char *buf;
  unsigned int len;
  va_list args;
  va_start(args, format);
  
  switch(configServeur.logDest){
    case UNDEF:
      accumulate++;
      msgs = (log_msg *) realloc(msgs, accumulate*sizeof(log_msg));
      buf = NULL;
      len = vsnprintf(buf, 0, format, args)+1;
      buf = (char *)malloc(len*sizeof(char));
      vsnprintf(buf, len, format, args);
      msgs[accumulate-1].buf = buf;
      msgs[accumulate-1].priority = priority;
      break;
    case STDERR:
      dumpLog();
      vfprintf(stderr, format, args);
      break;
    case SYSLOG:
      dumpLog();
      vsyslog(priority, format, args);
      break;
    case BOTH:
      dumpLog();
      vfprintf(stderr, format, args);
      vsyslog(priority, format, args);
      break;
  }
  
  va_end(args);
}

char *logDestToStr(log dest){

    switch(dest){
        case SYSLOG:
            return "syslog";
            break;
        case STDERR:
            return "stderr";
            break;
        case BOTH:
            return "both";
            break;
        default:
            return "undef";
            break;
    }
    
    
}
