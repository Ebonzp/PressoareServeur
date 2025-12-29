#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>


#include "main.h"
#include "traitementClient.h"
#include "logging.h"

int parseCommande(safeMessage *m, char **reponse, int *fin){
  int i;
  cmd c;

  logging(LOG_NOTICE, "Parse de la commande: %s.\n", m->safeBuffer);

  for(i=0; i<nbCommandes; i++){
    c = commandes[i];
    if( strncmp(m->safeBuffer, c.texte, c.lg) == 0){
      break;
    }
  }

  if(i == nbCommandes){
    logging(LOG_NOTICE, "Commande inconnue.\n");
    if(reponse != NULL)
      *reponse = alloc("UNKNOWN\n");
  }
  else{
    logging(LOG_NOTICE, "Traitement d'une commande: %s.\n", c.texte);
    m->debut += c.lg;
    m->len -= c.lg;
    doCommande(c, m,  reponse, fin);
  }

  return 0;
}

int sanitizeBuffer(char *unsafeBuffer, char **reponse, int* fin){
  safeMessage msg;
  int res=0;
  // Fin de chaîne
  int eos=-1;

  msg.len = strlen(unsafeBuffer);
  msg.debut = 0;
  msg.src = unsafeBuffer;
  msg.dst = (char *)&(msg.safeBuffer);
  if(configServeur.debug)
    fprintf(stderr, "Vérification d'une entrée de longueur %d\n", msg.len);

  if(msg.len > BUFFERLENGTH){
    return -BUFFERTOOLONG;
  }
  else{
    for(msg.i=0; msg.i<=msg.len; msg.i++){
#ifdef SSP
      if(configServeur.debug)
        printf(stderr, "src=%p dst=%p &RET=%p RET=%x i=%d len=%d: 0x%.2x\n", msg.src, msg.dst, (&eos+65), *(&eos+65), msg.i, msg.len, (unsigned char)*(msg.src));
#else
      if(configServeur.debug)
        fprintf(stderr, "src=%p dst=%p &RET=%p RET=%x i=%d len=%d: 0x%.2x\n", msg.src, msg.dst, (&eos+64), *(&eos+64), msg.i, msg.len, (unsigned char)*(msg.src));
#endif
      if(!isprint(*(msg.src))){
        logging(LOG_WARNING, "Caractère non imprimable détectée.\n");
        if(eos == -1)
          eos = msg.i;
      }
      *(msg.dst) = *(msg.src);
      msg.src++;
      msg.dst++;
    }
  }

  if(eos != -1){
    logging(LOG_WARNING, "Mise à zéro du premier caractère non imprimable à la position: %d.\n", eos);
    msg.safeBuffer[eos]='\0';
  }
  msg.len=strlen(msg.safeBuffer);
  res = parseCommande(&msg, reponse, fin);

  return res;
}

void traitementClient(int fds[]){  
  // Implementation du protocole
  int i, nbbytes, res, fin=0;
  char *buffer, *reponse, *tmp;
  int len;
  int pos=0;
  int delta=READSTEPLENGTH;

  // Initialize client state.
  initState();
  
  res = fchdir(fds[DATADIR]);
  if(res < 0){
    logging(LOG_CRIT, "Impossible de se positionner dans le répertoire de données: %s.\n", strerror(errno));
    exit(-1);
  }

  initCommandes();

  len = delta;
  buffer = (char *)malloc(len*sizeof(char));

  while(fin == 0){
    if(configServeur.debug)
      fprintf(stderr,"len %d pos: %d ",len,pos);
    nbbytes = read(fds[SOCKFD],buffer+pos,len-pos);
    if(configServeur.debug)
      fprintf(stderr,"nbbytes: %d\n",nbbytes);
    
    if(nbbytes<0){
      logging(LOG_CRIT, "Erreur de lecture sur la socket: %s.\n", strerror(errno));
      exit(-1);
    }
    if(nbbytes == 0){
        if(len-pos == 0){
            len+=delta;
            buffer=(char *)realloc(buffer, len);
        }
        else{
            // Plus rien a lire
            logging(LOG_NOTICE,"Plus rien à lire sur la socket.\n");
            exit(0);
        }
    }
    else if(nbbytes == len-pos){
      len+=delta;
      buffer=(char *)realloc(buffer, len);
    }
    
    
    // On a len-pos > nbbytes (*)
    
    int detected = 0;
    int detectedpos = -1;
    
    for(i=pos; i<pos+nbbytes; i++){
        if(buffer[i]=='\n'){
            if(configServeur.debug)
                fprintf(stderr,"Detection d'un retour a la ligne: %d\n",i);
            //Suppression du '\n"
            buffer[i]='\0';
        
            res = sanitizeBuffer(buffer+detectedpos+1, &reponse, &fin);
            if(res < 0){
                logging(LOG_CRIT,"Entrée suspicieuse.\n");
                exit(0);
            }
            
            logging(LOG_NOTICE, "Envoi de la réponse: %s.\n", reponse);
            res = strlen(reponse);
            write(fds[SOCKFD], reponse, res);
            free(reponse);
            if(fin == 1){
                goto end;
            }
            detected = 1;
            detectedpos = i;
        }
    } 
     
    if(!detected){
        pos+=nbbytes;
    }
    else{
	  // (boucle for) pos <= detectedpos < pos+nbbytes
	  // (=>) -pos - nbbytes < -detectedpos <= -pos
	  // (=>) len - pos - nbbytes < len - detectedpos
	  // (par *) nbbytes < len - pos
	  // (=>) 0 < len - pos - nbbytes 
	  // (=>) 0 < len - pos - nbbytes < len - detectedpos
	  // (=>) len - detectedpos > 0
	  
	  if(configServeur.debug)
            fprintf(stderr,"Avant allocation nouveau buffer: detectedpos=%d len=%d pos=%d nbbytes=%d\n",detectedpos,len,pos,nbbytes);
	  tmp = (char *)malloc(len-detectedpos-1);
	  memcpy(tmp, buffer+detectedpos+1,len-detectedpos-1);
	 
	  free(buffer);
	  buffer = tmp;
	  pos=pos+nbbytes-detectedpos-1;
	  len=len-detectedpos-1;
	  
      if(configServeur.debug)
            fprintf(stderr,"Apres allocation nouveau buffer: detectedpos=%d len=%d pos=%d nbbytes=%d\n",detectedpos,len,pos,nbbytes);
      }
      
  }
  
  end:
    return;
  
}
