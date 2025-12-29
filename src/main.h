#ifndef MAIN_H
#define MAIN_H

#include "logging.h"

#define DEFAULTPORT 5000
#define UNDEFINED -1
#define NXON 1
#define NXOFF 0

typedef enum randomization_t{
  OFF = 0,
  ON = 1 ,
  FULL = 2,
} randomization;

typedef enum fdtype_t{
    SOCKFD=0,
    DATADIR,
    FILEDB,
    MEMDB,
    LASTFD,
} fdtype;

typedef struct config_t{
  int port;
  int fds[LASTFD];
  randomization rand;
  int nx;
  log logDest;
  unsigned char debug;
} config;

extern config configServeur;
extern volatile int sigpipe;

#endif
