#ifndef AUTH_H
#define AUTH_H

#include <openssl/sha.h>

#include "users.h"

#define PASSWORD_OK 0
#define WRONG_PASSWORD -1

typedef enum authState_t {INIT=0, CHALLENGE_SENT, CHALLENGE_RECV, AUTHENTIFIED} authState;

unsigned char authenticate(user *user, unsigned int challenge, char *answer);

#endif
