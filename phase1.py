import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import sys

import json

with open("data.json") as f:
    data = json.load(f)

API_URL = "http://10.92.52.175:5000/"

stuID = data["stuID"]  ## Change this to your ID number
# generate random Sa once in range (0,n-1)
Sa = data["Sa"]

Sp = data["Sp"]

serverSPKx = data["serverSPKx"]

serverSPKy = data["serverSPKy"]

curve = Curve.get_curve("secp256k1")
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b


# generate random Sa once in range (0,n-1)

# server's Identitiy public key
IKey_Ser = Point(
    93223115898197558905062012489877327981787036929201444813217704012422483432813,
    8985629203225767185464920094198364255740987346743912071843303975587695337619,
    curve,
)

Q = Sa * P

SPKpublic = Sp * P
# Send Public Identitiy Key Coordinates and corresponding signature
def IKRegReq(h, s, x, y):
    mes = {"ID": stuID, "H": h, "S": s, "IKPUB.X": x, "IKPUB.Y": y}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "IKRegReq"), json=mes)
    if (response.ok) == False:
        print(response.json())


# Send the verification code
def IKRegVerify(code):
    mes = {"ID": stuID, "CODE": code}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "IKRegVerif"), json=mes)
    if (response.ok) == False:
        raise Exception(response.json())
    print(response.json())


# Send SPK Coordinates and corresponding signature
def SPKReg(h, s, x, y):
    mes = {"ID": stuID, "H": h, "S": s, "SPKPUB.X": x, "SPKPUB.Y": y}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "SPKReg"), json=mes)
    if (response.ok) == False:
        print(response.json())
    else:
        res = response.json()
        return res["SPKPUB.X"], res["SPKPUB.Y"], res["H"], res["S"]


# Send OTK Coordinates and corresponding hmac
def OTKReg(keyID, x, y, hmac):
    mes = {"ID": stuID, "KEYID": keyID, "OTKI.X": x, "OTKI.Y": y, "HMACI": hmac}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "OTKReg"), json=mes)
    print(response.json())
    if (response.ok) == False:
        return False
    else:
        return True


# Send the reset code to delete your Identitiy Key
# Reset Code is sent when you first registered
def ResetIK(rcode):
    mes = {"ID": stuID, "RCODE": rcode}
    print("Sending message is: ", mes)
    response = requests.delete("{}/{}".format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if (response.ok) == False:
        return False
    else:
        return True


# Sign your ID  number and send the signature to delete your SPK
def ResetSPK(h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.delete("{}/{}".format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if (response.ok) == False:
        return False
    else:
        return True


# Send the reset code to delete your Identitiy Key
def ResetOTK(h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.delete("{}/{}".format(API_URL, "ResetOTK"), json=mes)
    if (response.ok) == False:
        print(response.json())


def signMessage(message):
    k = random.randint(1, n - 2)
    R = k * P
    r = R.x % n
    if type(message) is int:
        messageByte = message.to_bytes((message.bit_length() + 7) // 8, byteorder="big")
    elif type(message) is bytes:
        messageByte = message
    else:
        messageByte = str(message).encode("utf-8")
    rByte = r.to_bytes((r.bit_length() + 7) // 8, byteorder="big")
    h = (
        int.from_bytes(SHA3_256.new(rByte + messageByte).digest(), byteorder="big")
    ) % n
    s = (k - Sa * h) % n
    return h, s


def verifyMessage(message, s, h):
    V = s * P + h * IKey_Ser
    v = V.x % n
    vByte = v.to_bytes((v.bit_length() + 7) // 8, byteorder="big")
    hprime = (
        int.from_bytes(SHA3_256.new(vByte + message).digest(), byteorder="big")
    ) % n
    return hprime == h


if len(sys.argv) < 2:
    print("usage: py .\phase1 <arg>")
    sys.exit(1)

arg = sys.argv[1]
if arg == "IKreg":
    h, s = signMessage(stuID)
    IKRegReq(h, s, Q.x, Q.y)

elif arg == "IKverify":
    code = int(sys.argv[2])
    IKRegVerify(code)

elif arg == "SPKreg":
    xBytes = SPKpublic.x.to_bytes((SPKpublic.x.bit_length() + 7) // 8, byteorder="big")
    yBytes = SPKpublic.y.to_bytes((SPKpublic.y.bit_length() + 7) // 8, byteorder="big")
    h, s = signMessage(xBytes + yBytes)
    serverX, serverY, serverH, serverS = SPKReg(h, s, SPKpublic.x, SPKpublic.y)
    if verifyMessage(
        serverX.to_bytes((serverX.bit_length() + 7) // 8, byteorder="big")
        + serverY.to_bytes((serverY.bit_length() + 7) // 8, byteorder="big"),
        serverS,
        serverH,
    ):
        print("Server SPK verified")
        data["serverSPKx"] = serverX
        data["serverSPKy"] = serverY
        with open("data.json", "w") as json_file:
            json.dump(data, json_file)
    else:
        print("Server SPK could not be verified")

else:
    print("usage: py .\phase1 <arg>")
