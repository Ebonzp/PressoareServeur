#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "main.h"
#include "utils.h"
#include "logging.h"
#include "message.h"
#include "commande.h"

cmd commandes[] = { 
    {.id = AUTH,    .texte="AUTH ",     .lg=0, .traitement = doAuth       },\
    {.id = CHALL,   .texte="CHALL ",    .lg=0, .traitement = doChallenge  },\
    {.id = CHALL,   .texte="LOGOUT",   .lg=0, .traitement = doLogout     },\
    {.id = ADDUSER, .texte="ADDUSER ",  .lg=0, .traitement = doAddUser    },\
    {.id = GET,     .texte="GET ",      .lg=0, .traitement = doGet        },\
    {.id = PUT,     .texte="PUT ",      .lg=0, .traitement = doPut        },\
    {.id = EXISTS,  .texte="EXISTS ",   .lg=0, .traitement = doExists     },\
    {.id = ECHO,    .texte="ECHO ",     .lg=0, .traitement = doEcho       },\
    {.id = QUIT,    .texte="QUIT",      .lg=0, .traitement = doQuit       }
};

                    
authState auth=INIT;
unsigned int challenge;
char *username=NULL;
int currentUserIndex;
// user *u=NULL;
int userDir = UNDEFINED;

unsigned int nbCommandes;


void initState(){
    auth=INIT;
    username=NULL;
    currentUserIndex=-1;
    userDir = UNDEFINED;
    srand(1);
}


user *getCurrentUser(){
    user *u;
    sem_t *lock;
    
    if(currentUserIndex == -1)
        return NULL;
    
    lock=&(users->lock);
    sem_wait(lock);
    
    u=&(users->users[currentUserIndex]);
    
    sem_post(lock);
    
    return u;
}

void initCommandes(){
  cmd *c;
  unsigned int i;

  nbCommandes = sizeof(commandes)/sizeof(cmd);
  if(configServeur.debug)
    fprintf(stderr, "Nombre de commandes: %d\n", nbCommandes);
  
  for(i=0; i<nbCommandes; i++){
    c = &(commandes[i]);
    c->lg = strlen(c->texte);
  }
}

int verifieNomRessource(char *nom){
  int len; 
  int i;

  len = strlen(nom);
  if(len == 0)
    return -1;

  for(i = 0; i< len; i++)
    if( isxdigit(nom[i]) == 0)
      return -1;

  return 0;
}

int verifieValeur(char *valeur){
  int len; 
  int i;

  len = strlen(valeur);
  if(len == 0)
    return -1;

  for(i = 0; i< len; i++)
    if( isdigit(valeur[i]) == 0)
      return -1;

  return 0;
}

int checkHash(char *hash){
    unsigned int len;
    char c;
    
    len = strlen(hash);
    if(len != 2*SHA_DIGEST_LENGTH)
        return -1;
    
    for(int i=0; i<2*SHA_DIGEST_LENGTH; i++){
        c=hash[i];
        if(!(  (('0' <= c) && (c <='9')) || (('a' <= c) && (c<= 'f')) || (('A' <= c) && (c <='F'))))
            return -1;
        if(('A' <= c) && (c<='F'))
            hash[i] = c-'A'+'a';
    }
    
    return 0;
}

void doAuth(safeMessage *msg, char **reponse, int *fin){
   unsigned int len, userlen;
   
   logging(LOG_NOTICE, "Exécution d'une commande AUTH.\n");
   
   switch(auth){
       case INIT:
          username = msg->safeBuffer+msg->debut;
          userlen = strlen(username);
          if(userlen == 0){
            logging(LOG_ERR, "Pas de nom d'utilisateur.\n");
            *reponse = alloc("NOUSERNAME\n");
            *fin=1;
            return;
          }
          
          currentUserIndex = lookupUserByIndex(username);
          
          fprintf(stderr, "Found user at index: %d\n", currentUserIndex);
          if (currentUserIndex == -1)
              logging(LOG_WARNING, "User not found: %s.\n", username);
          
          challenge = (unsigned int)rand();
          *reponse = NULL;
          len = snprintf(*reponse, 0, "CHALLENGE %d\n",challenge)+1;
          *reponse = (char *)malloc(sizeof(char)*len);
          snprintf(*reponse, len, "CHALLENGE %d\n", challenge);
          auth = CHALLENGE_SENT;
          return;
       default:
          logging(LOG_WARNING, "Authentication state: %d.\n", auth);
          *reponse = alloc("NOTAUTHENTIFIED\n");
          *fin=1;
          return;
   }
}

void doChallenge(safeMessage *msg, char **reponse, int *fin){
   char *answer;
   unsigned int answerLen=0;
   int ok;
   user *u;
    
   logging(LOG_NOTICE, "Exécution d'une commande CHALL.\n");
   
   u = getCurrentUser();
   
   if (u == NULL){
        logging(LOG_ERR, "User is undefined\n");
        *reponse = alloc("ERROR\n");
        *fin=1;
        return;
   }
   
   switch(auth){
       case CHALLENGE_SENT:
          answer = msg->safeBuffer+msg->debut;
          answerLen = strlen(answer);
          if(answerLen == 0){
            logging(LOG_ERR, "Pas de réponse au défi pour l'utilisateur: %s.\n", u->username);
            *reponse = alloc("NOCHALLENGE\n");
            *fin=1;
            return;
          }
          
          fprintf(stdout, "Trying to authenticate user: %p for challenge: %d. Answer: %s\n", u, challenge, answer);
          ok = authenticate(u, challenge, answer);
          fprintf(stdout, "Authentication success:%d", ok);
          
          if(ok == PASSWORD_OK){
            userDir = openat(configServeur.fds[DATADIR], u->username, O_DIRECTORY | __O_PATH);
            if(userDir < 0){
                logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données de l'utilisateur %s: %s.\n", u->username, strerror(errno));
                *reponse = alloc("DIRECTORYNOTOPENED\n");
                *fin = 1;
                return;
            }
            *reponse = alloc("OK\n");
            auth = AUTHENTIFIED;
            return;
          }
          
          *reponse = alloc("NOTAUTHENTIFIED\n");
          *fin=1;
          return;
          
       default:
          *reponse = alloc("ERROR\n");
          *fin=1;
          return;
   }
}

void doLogout(safeMessage *msg, char **reponse, int *fin){
  logging(LOG_NOTICE, "Exécution de la commande LOGOUT.\n");

  auth = INIT;
  *reponse = alloc("BYE\n");
  *fin = 0;
}

void doAddUser(safeMessage *msg, char **reponse, int *fin){
  char *name, *espace, *hash;
  int len;
  int dir;
  user *cu, *u;
  
  logging(LOG_NOTICE, "Exécution d'une commande ADDUSER.\n");
  
  if(auth != AUTHENTIFIED){
    logging(LOG_ERR, "Utilisateur non authentifié.\n");
    *reponse = alloc("NOTAUTHENTIFIED\n");
    *fin=1;
    return;
  }
  
  cu = getCurrentUser();
   
  if (cu == NULL){
        logging(LOG_ERR, "User is undefined\n");
        *reponse = alloc("ERROR\n");
        *fin=1;
        return;
   }
  
  if(! cu->is_admin){
    logging(LOG_ERR, "L'utilisateur %s ne possède pas les droits d'administration.\n", cu->username);
    *reponse = alloc("NOTADMIN\n");
    *fin=1;
    return;
  }
  
  name = msg->safeBuffer+msg->debut;
  espace = strchr(name, ' ');
  if(espace == NULL){
    *reponse = alloc("HASHNOTSPECIFIED\n");
    return;
  }
  espace[0]='\0';

  len = strlen(name);
  if(len < msg->len){
    msg->debut += len+1;
    msg->len -= len+1;
    hash = msg->safeBuffer + msg->debut;
  }
  else{
    *reponse = alloc("HASHNOTSPECIFIED\n");
    return;
  }
  
  logging(LOG_NOTICE, "Trying to add user: %s with hash: %s\n", name, hash);

  if(checkHash(hash) <0){
    *reponse = alloc("ILLFORMEDHASH\n");
    return;
  }
  
  // Vérifie si l'utilisateur n'existe pas déjà ? 
  
  u = lookupUserByAddr(name);
  
  logging(LOG_NOTICE, "Found user: %p\n", u);
  
  if ( u != NULL){
      *reponse = alloc("USERALREADYEXISTS\n");
      return;
  }

  
  // Création d'un répertoire pour l'utilisateur concerné.
  dir = openat(configServeur.fds[DATADIR], name, O_DIRECTORY | __O_PATH);
  if(dir < 0){
    if(errno == ENOENT){
      logging(LOG_NOTICE, "Le répertoire de stockage des données de l'utilisateur %s n'existe pas.\n", name);
      dir = mkdirat(configServeur.fds[DATADIR], name, S_IRWXU);
      if(userDir <0){
        logging(LOG_CRIT, "Impossible de créer le répertoire de données pour l'utilisateur %s: %s.\n", name, strerror(errno));
        *reponse = alloc("DIRECTORYNOTCREATED\n");
        *fin = 1;
        return;
      }
      dir = openat(configServeur.fds[DATADIR], name, O_DIRECTORY | __O_PATH);
      if(dir < 0){
        logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données de l'utilisateur %s: %s.\n", name, strerror(errno));
        *reponse = alloc("DIRECTORYNOTOPENED\n");
        *fin = 1;
        return;
      }
    }
    else{
      logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données de l'utilisateur %s: %s.\n", name, strerror(errno));
      *reponse = alloc("DIRECTORYNOTOPENED\n");
      *fin = 1;
      return; 
    }
  }
  
  // We are able to open the user's directory.
  close(dir);
  
  // Add user to database.
  
  addUser(configServeur.fds[MEMDB], name, hash, 0);
  
  // Réécrire la base de données.
  
  dumpDB();
  saveDB();
  
  *reponse = alloc("OK\n");
  return;
}

void doGet(safeMessage *msg, char **reponse, int *fin){
  char *nom;
  char buffer[1024];
  int fd, res;
  unsigned int len;

  logging(LOG_NOTICE, "Exécution d'une commande GET.\n");
  
  if(auth != AUTHENTIFIED){
    logging(LOG_ERR, "Utilisateur non authentifié.\n");
    *reponse = alloc("NOTAUTHENTIFIED\n");
    *fin=1;
    return;
  }
  
  if(userDir == UNDEFINED){
    logging(LOG_ERR, "Répertoire utilisateur non ouvert.\n");
    *reponse = alloc("NOUSERDIRECTORY\n");
    *fin=1;
    return; 
  }

  nom = msg->safeBuffer+msg->debut;
  if(verifieNomRessource(nom) <0){
    *reponse = alloc("ILLEGALNAME\n");
    return;
  }

  fd = openat(userDir, nom, O_RDONLY);
  if(fd < 0){
    logging(LOG_WARNING, "Impossible d'ouvrir le fichier %s: %s.\n", nom, strerror(errno));
    *reponse = alloc("RESOURCENOTFOUND\n");
    return;
  }

  res = read(fd, buffer, 1023);
  if(res < 0){
    logging(LOG_WARNING, "Impossible d'ouvrir le fichier %s: %s.\n", nom, strerror(errno));
    *reponse = alloc("RESOURCENOTREADABLE");
    return;
  }

  buffer[res]='\0';
  close(fd);
  len = snprintf(*reponse, 0, "OK: %s\n", buffer)+1;
  if(configServeur.debug)
    fprintf(stderr, "Longueur nécessaire: %d\n", len);
  *reponse = (char *)malloc(sizeof(char) * len);
  snprintf(*reponse, len, "OK: %s\n", buffer);
  *fin=0;
}

void doExists(safeMessage *msg, char **reponse, int *fin){
  char *nom;
  struct stat s;
  int res;

  logging(LOG_NOTICE, "Exécution d'une commande EXISTS.\n");
  
  if(auth!=AUTHENTIFIED){
    logging(LOG_ERR, "Utilisateur non authentifié.\n");
    *reponse = alloc("NOTAUTHENTIFIED\n");
    *fin=1;
    return;
  }
 
  if(userDir == UNDEFINED){
    logging(LOG_ERR, "Répertoire utilisateur non ouvert.\n");
    *reponse = alloc("NOUSERDIRECTORY\n");
    *fin=1;
    return; 
  }
  
  
  nom = msg->safeBuffer+msg->debut;
  if(verifieNomRessource(nom) <0){
    *reponse = alloc("ILLEGALNAME\n");
    return;
  }

  res = fstatat(userDir, nom, &s, 0);
  if(res < 0){
    *reponse = alloc("RESOURCENOTFOUND\n");
    return;
  }

  if(!S_ISREG(s.st_mode)){
    *reponse = alloc("RESOURCENOTFOUND\n");
    return;
  }

  *reponse = alloc("OK\n");
  *fin=0;
}

void doPut(safeMessage *msg, char **reponse, int *fin){
  char *cle, *valeur, *espace;
  int fd;
  int len;
  int res;

  logging(LOG_NOTICE, "Exécution d'une commande PUT.\n");
  
  if(auth!=AUTHENTIFIED){
    logging(LOG_ERR, "Utilisateur non authentifié.\n");
    *reponse = alloc("NOTAUTHENTIFIED\n");
    *fin=1;
    return;
  }

  if(userDir == UNDEFINED){
    logging(LOG_ERR, "Répertoire utilisateur non ouvert.\n");
    *reponse = alloc("NOUSERDIRECTORY\n");
    *fin=1;
    return; 
  }
  
  cle = msg->safeBuffer+msg->debut;
  espace = strchr(cle, ' ');
  if(espace == NULL){
    *reponse = alloc("VALUENOTFOUND\n");
    return;
  }
  espace[0]='\0';

  len = strlen(cle);
  if(verifieNomRessource(cle) <0){
    *reponse = alloc("ILLEGALNAME\n");
    return;
  }

  if(len < msg->len){
    msg->debut += len+1;
    msg->len -= len+1;
    valeur = msg->safeBuffer + msg->debut;
  }
  else{
    *reponse = alloc("VALUENOTFOUND\n");
    return;
  }

  if(verifieValeur(valeur) <0){
    *reponse = alloc("ILLEGALVALUE\n");
    return;
  }

  len = strlen(valeur);

  if(configServeur.debug)
    fprintf(stderr, "Valeur à écrire: %s\n", valeur);

  fd = openat(userDir, cle, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR);
  if(fd < 0){
    logging(LOG_WARNING, "Impossible d'ouvrir le fichier %s: %s.\n", cle, strerror(errno));
    *reponse = alloc("RESOURCEMAYEXISTS\n");
    return;
  }

  res = write(fd, valeur, len);
  if(res < 0){
    logging(LOG_WARNING, "Impossible d'écrire dans le fichier %s: %s.\n", cle, strerror(errno));
    *reponse = alloc("WRITEERROR\n");
    return;
  }

  close(fd);

  *reponse = alloc("OK\n");
  *fin=0;
}

void doQuit(safeMessage *msg, char **reponse, int *fin){
  logging(LOG_NOTICE, "Exécution d'une commande QUIT.\n");

  *reponse = alloc("BYE\n");
  *fin = 1;
}

void doEcho(safeMessage *msg, char **reponse, int *fin){
  int len;
  char *echo;

  logging(LOG_NOTICE, "Exécution d'une commande ECHO.\n");

  echo = msg->safeBuffer+msg->debut;
  len = snprintf(*reponse, 0, echo)+1;
  *reponse = (char *)malloc(sizeof(char)*len);
  snprintf(*reponse, len, echo);
  *fin=0;
}

void doCommande(cmd c, safeMessage *msg, char **reponse, int *fin){
  c.traitement(msg, reponse, fin);
}
