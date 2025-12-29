#ifndef USERS_H
#define USERS_H

#include <semaphore.h>

#define MAX_USERNAME_LENGTH 100

#define NO_DATABASE -1
#define REWIND_ERROR -2
#define DATABASE_READ_ERROR -3
#define DATABASE_PARSE_ERROR -4
#define HOMEDIR_ERROR -5

typedef struct user_t{
    // Username
    char username[MAX_USERNAME_LENGTH+1];
    // Hashed password stored under the form of an C characters chain of an hexadecimal representation of binary hash.
    // C chain is null terminated (hence +1).
    // One byte of data is represented by two characters in [0-9,A-F].
    char hash[2*SHA_DIGEST_LENGTH+1];
    // Administrator == 1
    unsigned char is_admin;
} user;

typedef struct usersdb_t {
    sem_t lock;
    unsigned int nb_pages;
    unsigned int nb_users;
    user users[];
} usersdb;

extern usersdb *users;

int initMemDB();
void reinstallMemDB();
int loadUsers();
void dumpDB();
int saveDB();
user *lookupUserByAddr(char *username);
int lookupUserByIndex(char *username);
void addUser(int fd, char *username, char *hash, unsigned int is_admin);


#endif
