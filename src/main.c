#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>



#include "utils.h"
#include "logging.h"
#include "auth.h"
#include "main.h"
#include "traitementServeur.h"
#include "traitementClient.h"


config configServeur = {.port = DEFAULTPORT, .fds={UNDEFINED, UNDEFINED, UNDEFINED, UNDEFINED}, .rand = FULL, .nx=NXON, .logDest=UNDEF, .debug=0};
volatile int sigpipe = 0;

usersdb *users = NULL;
const char dbentry[] = "admin:d033e22ae348aeb5660fc2140aec35850c4da997:1:\n";


void sigPipeHandler(int signum){
  if(signum == SIGPIPE)
    sigpipe = 1;
}

void sigChildHandler(int signum){
  if(signum == SIGCHLD)
    logging(LOG_DEBUG, "Reception du signal SIGCHILD.\n");
}

void sigSegvHandler(int signum, siginfo_t *info, void *context){
  if(signum == SIGSEGV){
    logging(LOG_CRIT, "Reception du signal SEGV a l'adresse: %p.\n", info->si_addr);
    exit(0);
  }
}

void donxoff(){
  void *addr;
  long pagesize;
  int res;

  pagesize = sysconf(_SC_PAGESIZE)-1;
  if(pagesize < 0){
    logging(LOG_CRIT, "Impossible de récupérer la taille des pages physiques: %s.\n", strerror(errno));
    exit(-1);
  }
  addr = &addr;
  addr = (void *)(((int) addr) & ~pagesize);
  logging(LOG_WARNING, "Désactivation de la protection de la pile à l'adresse: %p.\n", addr);
  res = mprotect(addr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
  if(res <0){
    logging(LOG_CRIT, "Impossible de modifier les protections de la pile: %s.\n", strerror(errno));
    exit(-1);
  }
}

void usage(const char *progname){
  fprintf(stderr, "Usage: %s [-h|--help] [(-p|--port) port d'écoute] [(-f | --fds) descripteurs de fichier] [(-r | --rand) 0|1|2 ] [(-x|--nx) 0|1] [(-l|--log) (stderr|syslog|both)]\n\
\t-h|--help:  ce message d'aide\n\
\t-p|--port int:  port d'écoute du serveur (%d par défaut)\n\
\t-r|--rand 0|1|2:  niveau de randomisation de l'espace d'adressage:\
\t\t 0: désactivation de l'ASLR,\n\
\t\t 1: ASLR activé,\n\
\t\t 2: changement d'espace d'adressage pour chaque connexion).\n\
\t-x|--nx 0|1:  activation du bit NX pour la pile (0: désactivé, 1: activé).\n\
\t-d|--data chemin: chemin vers le répertoire des données utilisateurs.\n\
\t-l|--log stderr|syslog|both: destination des journaux internes.\n\
\t-D|--debug: affichage d'information de débuggage supplémentaires.\n\
\t-f|--fds int,int,int,int : option interne au fonctionnement du serveur qui sert à passer les descripteurs de fichiers à utiliser pour:\n\
\t\t 1. communiquer avec le client.\n\
\t\t 2. le répertoire servant à stocker les données utilisateur.\n\
\t\t 3. la base de données des utilisateurs (fichier)\n\
\t\t 4. la base de données des utilisateurs (en mémoire partagée).\n",
            progname, DEFAULTPORT);
}

int main(int argc, char * const argv[]){
  int res;
  int randomization = UNDEFINED;
  int port=UNDEFINED;
  char *service = NULL;
  int c;
  int optionIndex;
  char *progname;
  int persona;
  int nx;
  int nbUsers;
  int usersDB;
  int usersDBMapFD;
  char *dataDir;
  int dir;
  char *fds, *fdsorig, *fd;
  int sock;
  int filed;
  struct stat statbuf;
  int fds_present = 0;
  
  progname = argv[0];
  dataDir = "./data";
  
  // Parsing des options
  struct option longOptions[] = {
    {"port",     required_argument, 0,  'p'},
    {"data", required_argument, 0, 'd'},
    {"fds",  required_argument, 0,  'f'},
    {"rand", required_argument, 0, 'r'},
    {"nx", required_argument, 0, 'x'},
    {"help", no_argument, 0, 'h'},
    {"log", required_argument, 0, 'l'},
    {"debug", no_argument, 0, 'D'},
    {0, 0, 0, 0}
  };
  opterr = 0;

  while(1){
    c = getopt_long(argc, argv, ":p:f:r:x:d:h:l:D", longOptions, &optionIndex);

    if (c == -1)
      break;

    switch(c){
      case 'h':
        usage(progname);
        exit(0);
        break;
      case 'p':
        port = atoi(optarg);
        if(port <= 0){
          logging(LOG_CRIT, "Le port doit avoir une valeur positive.\n");
          dumpLog();
          usage(progname);
          exit(-1);
        }
        configServeur.port = port;
        break;
      case 'd':
        dataDir = optarg;
        break;
      case 'f':
        fds_present = 1;
        fds = strdup(optarg);
        fdsorig = fds;
        for(fdtype i = SOCKFD; i<LASTFD; i++){
            fd = strtok(fds, ",");
         
            if(fd == NULL){
                logging(LOG_CRIT, "Pas suffisamment de descripteurs de fichiers passés en argument.\n");
                dumpLog();
                usage(progname);
                exit(-1);
            }
            
            filed = atoi(fd);
            
            if(filed <=0){
                logging(LOG_CRIT, "Un descripteur de fichier doit avoir une valeur positive.\n");
                dumpLog();
                usage(progname);
                exit(-1);
            }
            
            res = fstat(filed, &statbuf);
            if(res < 0){
                logging(LOG_CRIT, "Descripteur de fichier invalide: %d (%s).\n", filed, strerror(errno));
                dumpLog();
                usage(progname);
                exit(-1);
            }
            
            logging(LOG_DEBUG, "Ajout du descripteur de fichier: %d", filed);
            
            configServeur.fds[i] = filed;
            
            fds = NULL;
        }
        
        if(strtok(NULL, ",") != NULL){
            logging(LOG_CRIT, "Trop de descripteur de fichiers passés en argument: %p.\n", fd);
            dumpLog();
            exit(-1);
        }
        
        free(fdsorig);
        
        break;
      case 'r':
        randomization = atoi(optarg);
        if( (randomization < OFF) || (randomization >FULL)){
          logging(LOG_CRIT, "Le paramètre de randomisation ne peut prendre que certaines valeurs.\n");
          dumpLog();
          usage(progname);
          exit(-1);
        }
        configServeur.rand = randomization;
        break;
      case 'x':
        nx = atoi(optarg);
        if(nx < 0 || nx > 1){
          logging(LOG_CRIT, "Le paramètre NX ne peut prendre que certaines valeurs.\n");
          dumpLog();
          usage(progname);
          exit(-1);
        }
        configServeur.nx = nx;
        break;
      case 'l':
        if(strcmp(optarg, "stderr")==0){
          configServeur.logDest = STDERR;
        }
        else if (strcmp(optarg, "syslog")==0){
          configServeur.logDest = SYSLOG;
        }
        else if (strcmp(optarg, "both")==0){
          configServeur.logDest = BOTH;
        }
        else{
          logging(LOG_CRIT, "Le paramètre de journalisation ne peut prendre que certaines valeurs.\n");
          dumpLog();
          usage(progname);
          exit(-1);
        }
        break;
      case 'D':
        configServeur.debug = 1;
        break;
      case ':':
        logging(LOG_CRIT, "Paramètre manquant pour l'option: -%c\n", optopt);
        dumpLog();
        usage(progname);
        exit(-1);
        break;
      case '?':
        logging(LOG_CRIT, "Option inconnue: -%c\n", optopt);
        dumpLog();
        usage(progname);
        exit(-1);
        break;
      default:
        logging(LOG_CRIT, "Option inconnue: -%c\n", optopt);
        dumpLog();
        usage(progname);
        exit(-1);
        break;
    }
  }
  
  // Si on n'a pas spécifié la destination des journaux, on les envoie vers la sortie d'erreur.
  if(configServeur.logDest == UNDEF)
    configServeur.logDest = STDERR;

  // Paramètres supplémentaires 
  if(optind < argc){
    logging(LOG_CRIT, "Option(s) inconnue(s): %s\n", argv[optind]);
    usage(progname);
    exit(-1);
  }

  if(port !=UNDEFINED && fds_present == 1){
    logging(LOG_CRIT, "Les options --port et --fds sont mutuellement exclusives.\n");
    usage(progname);
    exit(-1);
  }

  if (configServeur.rand == OFF){
    persona = personality(0xFFFFFFFF);
    if (persona == -1){
      logging(LOG_CRIT, "Impossible de retrouver la personnalité Linux du serveur: %s.\n", strerror(errno));
      exit(-1);
    }
    // A-t-on déjà coupé la randomisation ?
    if ( (persona & ADDR_NO_RANDOMIZE) == 0){
      // Non: on coupe la randomisation.
      persona = persona | ADDR_NO_RANDOMIZE;
      persona = personality(persona);
      if (persona == -1){
        logging(LOG_CRIT, "Impossible de modifier la personnalité Linux du serveur: %s.\n", strerror(errno));
        exit(-1);
      }
      logging(LOG_NOTICE, "Réexécution (avec la randomisation coupée) sur même port.\n");
      if(configServeur.debug)
        res = execl(progname, progname, "-p", intToStr(configServeur.port), "-d", dataDir, "-r", "0", "-x", intToStr(configServeur.nx), "-l", logDestToStr(configServeur.logDest), "-D", NULL);
      else
        res = execl(progname, progname, "-p", intToStr(configServeur.port), "-d", dataDir, "-r", "0", "-x", intToStr(configServeur.nx), "-l", logDestToStr(configServeur.logDest), NULL);
      if(res < 0){
        logging(LOG_CRIT, "Impossible de se réexécuter en coupant la randomisation: %s\n", strerror(errno));
        exit(-1);
      }
    }
    else{
      logging(LOG_NOTICE, "La randomisation est coupée.\n");
    }
  }

  if(configServeur.nx == NXOFF)
    donxoff();

  if(fds_present == 1){
    logging(LOG_NOTICE, "Traitement d'une requête client.");
    reinstallMemDB(configServeur.fds[MEMDB]);
    traitementClient(configServeur.fds);
  }
  
  dir = open(dataDir, O_DIRECTORY | __O_PATH);
  if(dir < 0){
    if(errno == ENOENT){
      logging(LOG_NOTICE, "Le répertoire de stockage des données n'existe pas.\n");
      dir = mkdir(dataDir, S_IRWXU);
      if(dir <0){
        logging(LOG_CRIT, "Impossible de créer le répertoire de données: %s.\n", strerror(errno));
        exit(-1);
      }
      dir = open(dataDir, O_DIRECTORY | __O_PATH);
      if(dir < 0){
        logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données: %s.\n", strerror(errno));
        exit(-1);
      }
    }
    else{
      logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données: %s.\n", strerror(errno));
      exit(-1);
    }
  }
  
  configServeur.fds[DATADIR] = dir;
  
  usersDB = openat(dir, "users.db", O_RDWR);
  if(usersDB < 0){
    if(errno == ENOENT){
        logging(LOG_WARNING, "Aucune base de données des utilisateurs: création d'une base minimale.\n");
        usersDB = openat(dir, "users.db", O_CREAT|O_RDWR, S_IWUSR|S_IRUSR);
        if (usersDB < 0){
            logging(LOG_CRIT, "Impossible de créer la base de donnée utilisateur: %s.\n", strerror(errno));
            exit(-1);
        }
    
        write(usersDB, dbentry, strlen(dbentry));
    }
    else{
      logging(LOG_CRIT, "Impossible d'ouvrir la base de données des utilisateurs: %s.\n", strerror(errno));
      exit(-1);
    }
  }
  
  configServeur.fds[FILEDB] = usersDB;
  
  usersDBMapFD = initMemDB();
  if(usersDBMapFD < 0){
    logging(LOG_CRIT, "Impossible de créer la base de données en mémoire.\n");
    exit(-1); 
  }
  
  configServeur.fds[MEMDB] = usersDBMapFD;
  
  
  nbUsers = loadUsers();
  if(nbUsers < 0){
    logging(LOG_CRIT, "Impossible de parser la base de données des utilisateurs: %s\n", strerror(errno));
    exit(-1);
  }
  
  if(configServeur.debug)
    dumpDB();

  struct sigaction action;
  action.sa_handler = sigPipeHandler;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  res = sigaction(SIGPIPE, &action, NULL);
  if(res < 0){
    logging(LOG_CRIT, "Impossible d'installer le gestionnaire de signale pour le signal SIGPIPE: %s.\n", strerror(errno));
    exit(-1);
  }
  
  action.sa_handler = NULL;
  action.sa_sigaction = sigSegvHandler;
  action.sa_flags = SA_SIGINFO;
  sigemptyset(&action.sa_mask);
  res = sigaction(SIGSEGV, &action, NULL);
    if(res < 0){
    logging(LOG_CRIT, "Impossible d'installer le gestionnaire de signale pour le signal SIGSEGV: %s.\n", strerror(errno));
    exit(-1);
  }

  action.sa_handler = sigChildHandler;
  action.sa_flags = 0;
  sigemptyset(&action.sa_mask);
  res = sigaction(SIGCHLD, &action, NULL);
  if(res < 0){
    logging(LOG_CRIT, "Impossible d'installer le gestionnaire de signale pour le signal SIGCHILD: %s.\n", strerror(errno));
    exit(-1);
  }

  if(argc == 2)
      port = atoi(argv[1]);

  service = intToStr(configServeur.port);

  sock = initialisation(service, configServeur.port);
  if(sock < 0){
    goto end;
  }

  configServeur.fds[SOCKFD]=sock;
  
  free(service);

  traitementServeur(configServeur.fds, argv[0]);

  end: 
    return -1;
}
