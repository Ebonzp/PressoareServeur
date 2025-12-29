#define _GNU_SOURCE
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>



#include "main.h"
#include "auth.h"
#include "logging.h"


unsigned int usersdb_nb_pages = 0;


int initMemDB(){
    int fd, res;
    
    fd = memfd_create("/users_db_mapping", 0);
    
    if(fd < 0){
        logging(LOG_CRIT, "Impossible to allocate shared memory file descriptor for users database: %s.\n", strerror(errno));
        goto err0;
    }
    
    logging(LOG_INFO, "File descriptor of memory mapping: %d\n", fd);
   
    res = ftruncate(fd, sysconf(_SC_PAGESIZE));
    
    if(res < 0){
        logging(LOG_CRIT, "Impossible to resize shared memory file descriptor for users database: %s.\n", strerror(errno));
        goto err1;
    }
    
    usersdb_nb_pages = 1;
    users = mmap(0, usersdb_nb_pages * sysconf(_SC_PAGESIZE), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    
    if(users == (void *)-1){
        logging(LOG_CRIT, "Impossible to mmap shared memory file descriptor for users database: %s.\n", strerror(errno));
        goto err1;
    }
    
    logging(LOG_INFO, "Users DB mapped at: %p\n", users);
    
    res = sem_init (&(users->lock), 1, 1);
    
    if(res < 0){
        logging(LOG_CRIT, "Impossible to create lock for users database: %s.\n", strerror(errno));
        goto err2;
    }
    
    logging(LOG_DEBUG, "Semaphore created at address: %p\n", &(users->lock));
    
    users->nb_users = 0;
    users->nb_pages = 1;
   
    return fd;
    
    err2:
        munmap(users, usersdb_nb_pages);
    err1:
        close(fd);
    err0:
        return -1;
    
}


void reinstallMemDB(int fd){
    
    // We map database on a single page to access it.
    users = mmap(0, sysconf(_SC_PAGESIZE), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    
    if(users == (void *)-1){
        logging(LOG_CRIT, "Impossible to mmap shared memory file descriptor for users database: %s.\n", strerror(errno));
        exit(-1);
    }
    
    fprintf(stdout, "Users DB mapped at: %p\n", users);
    
    sem_wait(&(users->lock));
    
    usersdb_nb_pages = users->nb_pages;
    
    // We remap database at its full size.
    users = mremap(users, sysconf(_SC_PAGESIZE), users->nb_pages*sysconf(_SC_PAGESIZE), MREMAP_MAYMOVE);
    if(users == MAP_FAILED){
        logging(LOG_CRIT, "Impossible to remap users database for growing: %s.\n", strerror(errno));
        exit(-1);
    }
        
    sem_post(&(users->lock));
}


// This function may eventually remap the users database in virtual space address of current process.
// Indeed the database may have grown larger than actual mapping.
// In that case, iterating over users will raise a segfault.
// This function must be called with users->lock held.
void updateDBMapping(){

    // Underlying anonymous file is larger than mapped memory !
    if(users->nb_pages > usersdb_nb_pages){
        users = mremap(users, usersdb_nb_pages*sysconf(_SC_PAGESIZE), users->nb_pages*sysconf(_SC_PAGESIZE), MREMAP_MAYMOVE);
        if(users == MAP_FAILED){
            logging(LOG_CRIT, "Impossible to remap users database for growing: %s.\n", strerror(errno));
            exit(-1);
        }
        
        usersdb_nb_pages = users->nb_pages ;
    }
}


// This function must be called with users->lock held.
void resizeDB(int fd, unsigned int nb_users){
    void *oldaddr;
    unsigned int sz, szl, pad, pgsz, npgs;
    int res;
    
    // We may resize the current mapping if in the current process it is smaller than necessary.
    // Since other processes may have grown it larger than the size in current process.
    updateDBMapping();
    
    pgsz = sysconf(_SC_PAGESIZE);
    sz = sizeof(usersdb) + nb_users*sizeof(user) ;
    szl = usersdb_nb_pages*pgsz;
    
    logging(LOG_DEBUG, "Actual size of in memory database: %d. Needed size: %d\n", szl, sz);
    
    // If we need to allocate more space for database
    if ( sz > szl  ){
        pad = sz % pgsz;
        
        if(pad == 0)
            npgs = sz / pgsz;
        else
            npgs = (sz + pgsz - pad) / pgsz;
        
        logging(LOG_DEBUG, "We need %d pages for in memory database.\n", npgs);
        
         
        res = ftruncate(fd, npgs*sysconf(_SC_PAGESIZE));
        
        if(res < 0){
            logging(LOG_CRIT, "Impossible to resize shared memory file descriptor for users database: %s.\n", strerror(errno));
            exit(-1);
        }
        
        users->nb_pages = npgs;
        oldaddr = users;
        users = mremap(users, usersdb_nb_pages*sysconf(_SC_PAGESIZE), npgs*sysconf(_SC_PAGESIZE), MREMAP_MAYMOVE);
        if(users == MAP_FAILED){
            logging(LOG_CRIT, "Impossible to remap users database for growing: %s.\n", strerror(errno));
            exit(-1);
        }
        
        // If the memory database has changed ...
        if(oldaddr != users){
            logging(LOG_DEBUG, "In memory database has changed its location. It is now at address: %p\n", users);
        }
        else{
            logging(LOG_DEBUG, "In memory database is still at address: %p\n", users);
        }
        
        usersdb_nb_pages = npgs ;
    }
}


void addUser(int memdbfd, char *username, char *hash, unsigned int is_admin){
    user *u;
    
    if(is_admin)
        logging(LOG_DEBUG, "Inserting administrator user. Username: %s / hash: %s\n", username, hash);
    else
        logging(LOG_DEBUG, "Inserting regular user. Username: %s / hash: %s\n", username, hash);

    sem_wait(&(users->lock));
    
    resizeDB(memdbfd, users->nb_users+1);
    
    u = &(users->users[users->nb_users]);
    logging(LOG_DEBUG, "Adding a new user at address %p\n", u);
    strncpy(u->username, username, MAX_USERNAME_LENGTH);
    strncpy(u->hash, hash, 2*SHA_DIGEST_LENGTH);
    u->hash[2*SHA_DIGEST_LENGTH]='\0';
    u->is_admin = is_admin;

    users->nb_users++;

    sem_post(&(users->lock));
}

              
int loadUsers(){
    FILE *fp;
    char *line = NULL;
    char *username, *hash, *isAdmin;
    unsigned int lhash, lusername;
    size_t len = 0;
    ssize_t read;
    user *u;
    unsigned int nbUsers = 0;
    unsigned int admin = 0;
    int dir;
    int fd;
    int res;
    
    logging(LOG_DEBUG,"Loading users from file database.\n");
    
    fd = dup(configServeur.fds[FILEDB]);
    if (fd < 0){
        logging(LOG_CRIT, "Impossible to duplicate file descriptor of users database.\n");
        return NO_DATABASE;
    }
    
    res = lseek(fd, 0, SEEK_SET);
    if(res < 0){
        logging(LOG_CRIT, "Impossible to rewind users database at beginning.\n");
        return REWIND_ERROR;
    }
    
    fp = fdopen(fd, "r");
    if (fp == NULL){
        logging(LOG_CRIT, "Impossible to open users database.\n");
        return NO_DATABASE;
    }
        
    while ((read = getline(&line, &len, fp)) != -1) {
        
        if(configServeur.debug)
            fprintf(stderr, "Retrieved line (of length %d): %s", read, line);
        
        username = strtok(line, ":");
        if(username == NULL){
            logging(LOG_CRIT, "Impossible to retrieve username for line: \"%s\" in users database.\n", line);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
     
        lusername = strlen(username);
        if(lusername > MAX_USERNAME_LENGTH){
            logging(LOG_CRIT, "Username for line: \"%s\" in users database is too long: %d > %d.\n", line, lusername, MAX_USERNAME_LENGTH);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
        
        
        hash = strtok(NULL, ":");
        if(hash == NULL){
            logging(LOG_CRIT, "Impossible to retrieve password hash for line: \"%s\" in users database.\n", line);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
        
        lhash = strlen(hash);
        if(lhash != 2*SHA_DIGEST_LENGTH){
            logging(LOG_CRIT, "Password hash for line: \"%s\" in users database has wrong length: %d (should be %d).\n", line, lhash, 2*SHA_DIGEST_LENGTH);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
        
        isAdmin = strtok(NULL, ":");
        if(isAdmin == NULL){
            logging(LOG_CRIT, "Impossible to retrieve admin status for line: \"%s\" in users database.\n", line);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
        
        admin = atoi(isAdmin);
        if( (admin !=0) && (admin != 1)){
            logging(LOG_CRIT, "Admin status (%d) for line: \"%s\" in users database is not valid (should be 0 or 1).\n", admin, line);
            free(line);
            fclose(fp);
            return DATABASE_PARSE_ERROR;
        }
        
       addUser(configServeur.fds[MEMDB], username, hash, admin);
        
        // Check if each user owns a personnal directory.
        dir = openat(configServeur.fds[DATADIR], username, O_DIRECTORY | __O_PATH);
        if(dir < 0){
            if(errno == ENOENT){
                logging(LOG_NOTICE, "Le répertoire de stockage des données de l'utilisateur %s n'existe pas.\n", username);
                dir = mkdirat(configServeur.fds[DATADIR], username, S_IRWXU);
                if(dir <0){
                    logging(LOG_CRIT, "Impossible de créer le répertoire de données pour l'utilisateur %s: %s.\n", username, strerror(errno));
                    free(line);
                    fclose(fp);
                    return HOMEDIR_ERROR;
                }
                dir = openat(configServeur.fds[DATADIR], username, O_DIRECTORY | __O_PATH);
                if(dir < 0){
                    logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données de l'utilisateur %s: %s.\n", username, strerror(errno));
                    free(line);
                    fclose(fp);
                    return HOMEDIR_ERROR;
                }
            }
            else{
                logging(LOG_CRIT, "Impossible d'ouvrir le répertoire de données de l'utilisateur %s: %s.\n", username, strerror(errno));
                free(line);
                fclose(fp);
                return HOMEDIR_ERROR; 
            }
        }
        
        // We were able to open home directory.
        close(dir);
    }
    
    free(line);
    
    // The underlying file descriptor is closed by side-effect.
    fclose(fp);
    
    if (ferror(fp)) {
        logging(LOG_CRIT, "Error during readling a line of users database.\n");
        return DATABASE_READ_ERROR;
    }
    
    
    if(configServeur.debug){
        fprintf(stderr, "Number of users: %d\n", users->nb_users);
    
        for(unsigned int i=0; i<nbUsers; i++){
            u = &(users->users[i]);
            fprintf(stderr, "Index: %d. Username: %s Hash: %s Admin:%d \n", i, u->username, u->hash, u->is_admin); 
        }
    }
    
    return nbUsers;
}


void dumpDB(){
    user *u;
    
    sem_wait(&(users->lock));
    
    // Database may have grown since last usage.
    // We might have to remap it to accomodate the new size
    // In that case users pointer will change !!!
    updateDBMapping();
    
    for(unsigned int i=0; i<users->nb_users; i++){
        u = &(users->users[i]);
        if(u->is_admin)
            logging(LOG_DEBUG, "Administrator user name: %s hash: %s.\n", u->username, u->hash);
        else
            logging(LOG_DEBUG, "Regular user name: %s hash: %s.\n", u->username, u->hash);
    }
    
    sem_post(&(users->lock));
}

user *lookupUserByAddr(char *username){
    user *u;
    
    sem_wait(&(users->lock));
    updateDBMapping();
    
    for (unsigned int i=0; i<users->nb_users; i++){
        u=&(users->users[i]);
        if(configServeur.debug)
            logging(LOG_DEBUG, "Searching username: %s. User: %p Current username: %s\n", username, u, u->username); 
        if (strcmp(u->username, username)==0){
            sem_post(&(users->lock));
            return u;
        }
    }
    
    sem_post(&(users->lock));
    
    // User not found
    return NULL;
}


int lookupUserByIndex(char *username){
    user *u;
    
    sem_wait(&(users->lock));
    updateDBMapping();
    
    for (unsigned int i=0; i<users->nb_users; i++){
        u=&(users->users[i]);
        if(configServeur.debug)
            logging(LOG_DEBUG, "Searching username: %s. User: %p Current username: %s\n", username, u, u->username); 
        if (strcmp(u->username, username)==0){
            sem_post(&(users->lock));
            return i;
        }
    }
    
    sem_post(&(users->lock));
    
    return -1;
}


int saveDB(){
    FILE *fp=NULL;
    user *u;
    int fd;
    
    logging(LOG_DEBUG, "Users DB fd: %d\n", configServeur.fds[FILEDB]);
    
    fd = dup(configServeur.fds[FILEDB]);
    fp = fdopen(fd, "w");
    
    if (fp == NULL){
        logging(LOG_CRIT, "Impossible to open users database.\n");
        close(fd);
        return NO_DATABASE;
    }
    
    fseek(fp, 0, SEEK_SET);
    
    sem_wait(&(users->lock));
    updateDBMapping();
    
    for(unsigned int i=0; i<users->nb_users; i++){
        u = &(users->users[i]);
        
        logging(LOG_DEBUG, "Saving %s:%s:%d:\n", u->username, u->hash, u->is_admin);
        fprintf(fp, "%s:%s:%d:\n", u->username, u->hash, u->is_admin);
    }
    
    sem_post(&(users->lock));
    
    fflush(fp);
    fclose(fp);
    
    return 0;
}

