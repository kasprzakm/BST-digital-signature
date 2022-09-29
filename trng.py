from subprocess import Popen, PIPE
import random


# Reads processor's current frequency,
# converts it to UTF-8 string,
# then hashes with SHA256.
# Returns integer value of random binary.

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


def rando(amount_of_bits: int = 8):
    p = Popen('True Random Number Generator.exe ' + str(amount_of_bits), stdout=PIPE, stdin=PIPE)
    result = int.from_bytes(p.stdout.readline().strip(), byteorder='big')
    return bytes(result)
