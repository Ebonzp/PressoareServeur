#ifndef MESSAGE_H
#define MESSAGE_H

// Note: doit être un multiple de 4
// Doit être juste un peu plus grand qu'un multiple de #READSTEPLENGTH
#define BUFFERLENGTH 200

typedef struct safeMessage_t{
  char safeBuffer[BUFFERLENGTH];
  int i;
  int len;
  char *dst;
  char *src;
  int debut;
} safeMessage;

#endif
