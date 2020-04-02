#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Source: 
# - Daniel pour la longeur du message
# - Abraham Rubinstein pour la base du script
# - https://github.com/VictorTruan/SU19-WLANSec-Lab2-WEP
#
# Author: Victor Truan, Jérôme Bagnoud | SWI - Labo 03 - Exo 02

from scapy.all import *
import binascii
from rc4 import RC4
from zlib import crc32

# Cle WEP AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
messageToEncrypt = "coucou"*6
UTF8 = 'utf8'
outputFilename = "output.cap"

arp = rdpcap('arp.cap')[0]

# RC4 seed est composé de IV+clé
iv = arp.iv
seed = iv+key

icv = crc32(bytes(messageToEncrypt, UTF8))

# Chiffrement RC4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(bytes(messageToEncrypt, UTF8) + struct.pack("<L", icv))

# Remplacement des champs dans le packet
arp.wepdata = ciphertext[:-4]
icvtmp = ciphertext[-4:]
arp.icv = struct.unpack("!L", icvtmp)[0]

# Ecriture du packet dans le fichier .cap
wrpcap(outputFilename, arp)

print("Packet was saved in 'output.cap' file")