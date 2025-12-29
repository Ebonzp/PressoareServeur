#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>




#include "main.h"
#include "auth.h"
#include "logging.h"

int hextohash(const char *hex, char hash[]){
    unsigned int len;
    char c1, c2;
    unsigned int v1, v2, v;
    
    len = strlen(hex);
    if(len != 2*SHA_DIGEST_LENGTH){
        logging(LOG_WARNING, "Length of hexadecimal form of SHA1 hash is wrong: %d (%d expected)", len, 2*SHA_DIGEST_LENGTH);
        return -1;
    }
    
    for(int i=0; i<SHA_DIGEST_LENGTH; i++){
        c1 = hex[2*i];

        if( !((c1>='0' && c1<='9') || ( c1>='a' && c1<='f') || (c1>='A' && c1<='F'))){
            logging(LOG_WARNING, "Wrong character in hexadecimal form of SHA1 hash: %c", c1);
        }

        v1=0;
        
        if((c1>='0' && c1<='9')){
            v1 = (unsigned int)c1 - (unsigned int)'0';
        }
            
        if((c1>='a' && c1<='f')){
            v1 = (unsigned int)c1 - (unsigned int)'a'+10;
        }
        
        if ((c1>='A' && c1<='F')){
            v1 = (unsigned int)c1 - (unsigned int)'A'+10;
        }
        
        c2 = hex[2*i+1];
        
        if( ! ((c2>='0' && c2<='9') || ( c2>='a' && c2<='f') || (c2>='A' && c2<='F'))){
            logging(LOG_WARNING, "Wrong character in hexadecimal form of SHA1 hash: %c", c2);
        }
        
        if((c2>='0' && c2<='9')){
            v2 = (unsigned int)c2 - (unsigned int)'0';
        }
            
        if((c2>='a' && c2<='f')){
            v2 = (unsigned int)c2 - (unsigned int)'a'+10;
        }
        
        if ((c2 >='A' && c2<='F')){
            v2 = (unsigned int)c2 - (unsigned int)'A'+10;
        }
        
        v=v1*16+v2;
        
        hash[i]=(char)v;
    }
    
    return 0;
}

char * hashtohex(unsigned char hash[]){
    char *res;
    unsigned char c;
    unsigned int v1,v2;
    char c1,c2;
    int i;
    
    res = malloc(2*SHA_DIGEST_LENGTH*sizeof(char)+1);
    
    for(i=0; i<SHA_DIGEST_LENGTH; i++){
        c=hash[i];
        v1=((unsigned int)c)%16;
        v2=((unsigned int)c)/16;
        
        if(v1<10){
            c1 = '0'+v1;
        }
        if(v1>=10){
            c1 = 'a'+v1-10;
        }
        
        if(v2<10){
            c2 = '0'+v2;
        }
        if(v2>=10){
            c2 = 'a'+v2-10;
        }
        
        res[2*i]=c2;
        res[2*i+1]=c1;
    }
    
    res[2*i]='\0';
    
    return res;
}



unsigned char authenticate(user *user, unsigned int challenge, char *answer){
    unsigned char *data;
    unsigned int len;
    unsigned char hash[SHA_DIGEST_LENGTH];
    char *hexa;
    unsigned char res = WRONG_PASSWORD;
    
    if(user == NULL)
        return WRONG_PASSWORD;
    
    data = NULL;
    len = snprintf((char *)data, 0, "%d%s", challenge, user->hash)+1;
    data = (unsigned char *)malloc(sizeof(unsigned char)*len);
    snprintf((char *)data, len, "%d%s", challenge, user->hash);
    
    // We only want to hash the string, not the terminating null character.
    // Hence length is (len-1).
    hexa = hashtohex(SHA1(data, len-1, hash));
    
    if(configServeur.debug)
        fprintf(stderr, "Challenge: %d Hashed password: %s Expected answer: %s Received answer: %s\n", challenge, user->hash, hexa, answer);
    
    if(strcmp(hexa, answer)==0)
       res = PASSWORD_OK;
    
    free(hexa);
    return res;
}

