bin_PROGRAMS=serveur

serveur_SOURCES= \
	utils.c utils.h \
	logging.c logging.h \
	users.h users.c \
	auth.c auth.h \
	main.c main.h \
	message.h \
	commande.h commande.c \
	traitementClient.c traitementClient.h \
	traitementServeur.c traitementServeur.h

serveur_CFLAGS = $(PTHREAD_CFLAGS)
serveur_LDADD = $(PTHREAD_LIBS)
