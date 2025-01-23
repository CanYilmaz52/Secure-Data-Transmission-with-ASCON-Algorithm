CONTIKI_PROJECT = udp-client udp-server
all: $(CONTIKI_PROJECT)

TARGET = sky

CONTIKI = ../..
include $(CONTIKI)/Makefile.include

# ascon.c dosyasını projeye dahil et
SRCFILES += ascon.c
OBJS += ascon.o
