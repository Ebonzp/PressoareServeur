#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "utils.h"
#include "logging.h"
#include "main.h"
#include "traitementClient.h"

int initialisation(char * service, int port){
  int res;
  logging(LOG_INFO, "Démarrage du serveur (à l'écoute sur le port %d).\n", port);
  
  int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
  if(fd < 0){
    logging(LOG_CRIT, "Impossible de créer une socket: %s.\n", strerror(errno));
    goto end;  
  }
  
  if(configServeur.debug)
    fprintf(stderr,"Recuperation de l'adresse de la machine.\n");
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;    /* IPv4 */
  hints.ai_socktype = SOCK_STREAM; /* TCP */
  hints.ai_flags = AI_PASSIVE|AI_NUMERICSERV;    /* For wildcard IP address */
  hints.ai_protocol = 0;          /* Any protocol */
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;
  
  struct addrinfo *result, *rp;
  res = getaddrinfo(NULL, service, &hints, &result);
  if(res < 0){
      logging(LOG_CRIT, "Impossible de recuperer l'adresse de la machine: %s.\n", strerror(errno));
      goto closefd;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    res = bind(fd, rp->ai_addr,rp->ai_addrlen);
    if(res == 0)
      break;
  }
  
  if(rp == NULL){
      logging(LOG_CRIT, "Impossible de lier la socket: %s.\n", strerror(errno));
      goto closefd;
  }
  freeaddrinfo(result);

  logging(LOG_INFO, "Liaison réussie.\n");

  res = listen(fd, 5);
  if(res < 0){
     logging(LOG_CRIT, "Impossible de passer en mode écoute: %s.\n", strerror(errno));
     goto closefd;
  }
  
  return fd;

  closefd:
    close(fd);
  end:
    return -1;
}

int gestionConnexion(int fds[], const char *executable){
  int newfd, res;
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(struct sockaddr_in);
  char ip[16];
  char port[6];
  char *fdsstr = NULL;
  char *nxstr = NULL;
  char *logDest = NULL;
  int len;

  logging(LOG_INFO, "Traitement d'une connexion entrante.\n");

  newfd = accept(fds[SOCKFD], (struct sockaddr *)&addr, &addrlen);
  if(newfd < 0){
      logging(LOG_CRIT, "Erreur lors de l'acceptation de la connexion: %s.\n", strerror(errno));
      return -1;
  }
  
  res = getnameinfo((struct sockaddr *)&addr, addrlen, ip, 16, port, 6,
		      NI_NUMERICHOST|NI_NUMERICSERV);
  if(res < 0){
    logging(LOG_CRIT, "Impossible de résoudre l'adresse IP de la connexion entrante: %s.\n", strerror(errno));
    close(newfd);
    return -1;
  }

  logging(LOG_INFO, "Connexion depuis %s:%s.\n", ip, port);

  res = fork();
  if(res < 0){
     logging(LOG_CRIT, "Impossible de créer un nouveau processus: %s.\n", strerror(errno));
     shutdown(newfd, SHUT_RDWR);
     close(newfd);
     return -1;
  }

  if(res == 0){
    // Pour le processus fils, la socket à traiter est celle sur laquelle on a accepté la connexion.
    configServeur.fds[SOCKFD] = newfd;
    logging(LOG_INFO, "Randomisation: %d.\n", configServeur.rand);
    switch(configServeur.rand){
      case OFF:
        logging(LOG_INFO, "Pas de randomisation: fork simple.\n");
        traitementClient(configServeur.fds);
        break;
      case ON:
        logging(LOG_INFO, "Randomisation partielle: fork simple.\n");
        traitementClient(configServeur.fds);
        break;
      case FULL:
        logging(LOG_INFO, "Randomisation complète.\n");
        fdsstr = NULL;
        len = snprintf(fdsstr, 0, "%d,%d,%d,%d", configServeur.fds[SOCKFD], configServeur.fds[DATADIR], configServeur.fds[FILEDB], configServeur.fds[MEMDB])+1;
        fdsstr = (char *) malloc(sizeof(char)*len);
        snprintf(fdsstr, len, "%d,%d,%d,%d", configServeur.fds[SOCKFD], configServeur.fds[DATADIR], configServeur.fds[FILEDB], configServeur.fds[MEMDB]);
        nxstr = intToStr(configServeur.nx);
        logDest = logDestToStr(configServeur.logDest);
        if (configServeur.debug){
            logging(LOG_INFO, "Réexécution du processus fils comme: %s -f %s -x %s -l %s -D.\n", executable, fdsstr, nxstr, logDest);
            res = execl(executable, executable, "-f", fdsstr, "-x", nxstr, "-l", logDest, "-D", NULL);
        }
        else{
            logging(LOG_INFO, "Réexécution du processus fils comme: %s -f %s -x %s -l %s.\n", executable, fdsstr, nxstr, logDest);
            res = execl(executable, executable, "-f", fdsstr, "-x", nxstr, "-l", logDest, NULL);
        }
        
        if (res < 0){
          logging(LOG_CRIT, "Impossible de renouveler l'espace d'adressage du processus: %s.\n", strerror(errno));
          shutdown(newfd, SHUT_RDWR);
          close(newfd);
          exit(-1);
        }
        break;
      default:
        logging(LOG_CRIT, "Valeur de randomisation inconnue: %d.\n", configServeur.rand);
        shutdown(newfd, SHUT_RDWR);
        close(newfd);
        exit(-1);
        break;
    }
  }

  close(newfd);
  return 0;
}

void traitementSignaux(){
  int status;
  pid_t pid;

  if(sigpipe == 1){
    logging(LOG_WARNING, "Reception du signal PIPE.\n");
    sigpipe = 0;
  }
  
  while(1){
    pid = waitpid(-1, &status, WNOHANG);
    if(pid > 0){
        logging(LOG_INFO, "Fin de traitement pour un processus fils (pid: %d) avec code de sortie: %d.\n", pid, WEXITSTATUS(status));
    }
    else if (pid <= 0){
        break;
    }
  }
  
}

void traitementServeur(int fds[], const char *executable){
 int res;
 fd_set set;
 sigset_t empty;
 
 FD_ZERO(&set);
 FD_SET(fds[SOCKFD], &set);
 sigemptyset(&empty);

 
  for(;;){
    FD_SET(fds[SOCKFD], &set);

    traitementSignaux();

    res = pselect(fds[SOCKFD]+1, &set, NULL, NULL, NULL, &empty); 

    if(res == -1){
      if( errno == EINTR){
        traitementSignaux();
      }
      else{
        logging(LOG_CRIT, "Erreur dans l'appel à pselect: %s.\n", strerror(errno));
        exit(-1);
      }
    }
    else if(res > 0){
      if(FD_ISSET(fds[SOCKFD], &set)){
        // Traitement d'une connexion
        gestionConnexion(fds, executable);
      }
    }
  }
}
