#ifndef CLIENT_H
#define CLIENT_H

#include "message.h"
#include "commande.h"

#define READSTEPLENGTH 2048
#define BUFFERTOOLONG 1



void traitementClient(int fds[]);

extern int nbCommandes;
extern cmd commandes[];

#endif
