# Source: 
# - Daniel pour la longeur du message
# - Abraham Rubinstein pour la base du script
# - https://github.com/VictorTruan/SU19-WLANSec-Lab2-WEP
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import binascii
from rc4 import RC4
from zlib import crc32

# Cle WEP AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'
messageToEncrypt = "coucou"*6

arp = rdpcap('arp.cap')[0]

# RC4 seed est composé de IV+clé
iv = arp.iv
seed = iv+key
outputFilename = "output.cap"

icv = crc32(bytes(messageToEncrypt, 'utf8')) & 0xffffffff

# Chiffrement RC4
cipher = RC4(seed, streaming=False)
ciphertext = cipher.crypt(bytes(messageToEncrypt, 'utf8') + struct.pack("<L", icv))

# Remplacement des champs dans le packet
arp.wepdata = ciphertext[:-4]
icvtmp = ciphertext[-4:]
arp.icv = struct.unpack("!L", icvtmp)[0]

# Ecriture du packet dans le fichier .cap
wrpcap(outputFilename, arp)
