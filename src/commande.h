#ifndef COMMANDE_H
#define COMMANDE_H

#include "message.h"
#include "auth.h"

typedef enum cmdID_t {AUTH=0, CHALL, ADDUSER, GET, PUT, EXISTS, ECHO, QUIT} cmdID;

typedef struct cmd_t{
  cmdID id;
  char * texte;
  unsigned int lg;
  void (* traitement)(safeMessage *, char**, int *);
} cmd;



void doAuth(safeMessage *, char **, int *);
void doChallenge(safeMessage *, char **, int *);
void doLogout(safeMessage *, char **, int *);
void doAddUser(safeMessage *, char **, int *);
void doGet(safeMessage *, char **, int *);
void doPut(safeMessage *, char **, int *);
void doEcho(safeMessage *, char **, int *);
void doExists(safeMessage *, char **, int *);
void doQuit(safeMessage *, char **, int *);
void doCommande(cmd, safeMessage *, char **, int *);
void initCommandes();
void initState();
char *alloc(const char *);

#endif
