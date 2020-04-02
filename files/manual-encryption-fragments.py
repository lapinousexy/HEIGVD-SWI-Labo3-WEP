#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Source: 
# - Daniel pour la longeur du message
# - https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
# - https://www.geeksforgeeks.org/copy-python-deep-copy-shallow-copy/
# - https://stackoverflow.com/questions/4794244/how-can-i-create-a-copy-of-an-object-in-python
#
# Author: Victor Truan, Jérôme Bagnoud | SWI - Labo 03 - Exo 03

from scapy.all import *
import binascii
import copy
from rc4 import RC4
from zlib import crc32

outputFilename = "output3.cap"
UTF8 = 'utf8'
key= b'\xaa\xaa\xaa\xaa\xaa'

secondMessage = "salut!"*6
thirdMessage = "hahaha"*6
firstMessage = "coucou"*6

arp = rdpcap('arp.cap')[0]

# RC4 seed est composé de IV+clé
iv = arp.iv
seed = iv+key

# Fonction utilisée pour créer des paquets chiffrés depuis le payload.
# data est le string que nous souhaitons avoir comme payload.
def createPacket(data):
    # Copying the original packet, source: https://www.geeksforgeeks.org/copy-python-deep-copy-shallow-copy/ + https://stackoverflow.com/questions/4794244/how-can-i-create-a-copy-of-an-object-in-python
    packetToSend = copy.copy(arp)

    icv = crc32(bytes(data, UTF8))

    # Chiffrement RC4
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(bytes(data, UTF8) + struct.pack("<L", icv))

    # Remplacement des champs dans le packet
    packetToSend.wepdata = ciphertext[:-4]

    icvtmp = ciphertext[-4:]
    packetToSend.icv = struct.unpack("!L", icvtmp)[0]

    return packetToSend

# Création d'une liste et ajout des paquets dans la liste.
packetsList = list()
packetsList.append(createPacket(firstMessage))
packetsList.append(createPacket(secondMessage))
packetsList.append(createPacket(thirdMessage))

i = 0
for packet in packetsList:
    if i != (len(packetsList) - 1):
        # Si c'est pas le dernier paquet, on change le bit de MF (More fragment)
        packet.FCfield |= 0x4
    
    # Comme indiqué dans la donnée, on utilise le champs SC pour augmenter le compteur de fragment.
    packet.SC += i
    i += 1

    # Source : https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
    # Ecriture du packet dans le fichier .cap
    wrpcap(outputFilename, packet, append=True)

print("Packet was saved in 'output3.cap' file")