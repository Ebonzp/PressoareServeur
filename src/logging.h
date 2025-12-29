#ifndef LOGGING_H
#define LOGGING_H

#include <syslog.h>

typedef enum log_t{
  UNDEF=0,
  SYSLOG=1,
  STDERR=2,
  BOTH=3,
} log;

extern void logging(int priority, const char *format, ...);
extern void dumpLog();
extern char *logDestToStr(log dest);

#endif
