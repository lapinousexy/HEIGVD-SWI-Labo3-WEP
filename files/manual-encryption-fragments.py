# Source: 
# - Daniel pour la longeur du message
#
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
from rc4 import RC4
from zlib import crc32


#Fonction utilisée pour crée des paquets chiffrés depuis le payload.
#data est le string que nous souhaitons avoir comme payload.
def createPacket(data):
    key= b'\xaa\xaa\xaa\xaa\xaa'
    arp = rdpcap('arp.cap')[0]
    packet = arp

    # RC4 seed est composé de IV+clé
    iv = packet.iv
    seed = iv+key
    
    icv = crc32(bytes(data, 'utf8')) & 0xffffffff

    # Chiffrement RC4
    cipher = RC4(seed, streaming=False)
    ciphertext = cipher.crypt(bytes(data, 'utf8') + struct.pack("<L", icv))

    # Remplacement des champs dans le packet
    packet.wepdata = ciphertext[:-4]
    icvtmp = ciphertext[-4:]
    packet.icv = struct.unpack("!L", icvtmp)[0]
    return packet



outputFilename = "output3.cap"

#Creation d'une liste et ajout des paquets dans la liste.
packetsToSend = list()
packetsToSend.append(createPacket("coucou"*6))
packetsToSend.append(createPacket("salut!"*6))
packetsToSend.append(createPacket("hahaha"*6))

i = 0
for packet in packetsToSend:
    if i != (len(packetsToSend) - 1):
        #Si c'est pas le dernier paquet, on change le bit de MF
        packet.FCfield |= 0x4
    #Comme indiqué dans la donnée, on utilise le champs SC pour augmenter le compteur de fragment.
    packet.SC += i
    i += 1
    #Source : https://stackoverflow.com/questions/7574092/python-scapy-wrpcap-how-do-you-append-packets-to-a-pcap-file
    # Ecriture du packet dans le fichier .cap
    wrpcap(outputFilename, packet, append=True)



