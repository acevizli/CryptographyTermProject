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
from Crypto.Cipher import AES,Counter
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

K_HMAC = data["K_HMAC"]

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



def sign0TK(zeroTKpublic):
    message = zeroTKpublic.x.to_bytes((zeroTKpublic.x.bit_length() + 7) // 8, byteorder="big") + zeroTKpublic.y.to_bytes((zeroTKpublic.y.bit_length() + 7) // 8, byteorder="big")
    hmac =  HMAC.new(key=K_HMAC.to_bytes((K_HMAC.bit_length() +7)//8, byteorder="big"),msg=message,digestmod=SHA256)
    return hmac.hexdigest()
def generate0TK(index):
    zeroTK = random.randint(1,n-1)
    zeroTKpublic = zeroTK * P
    signature = sign0TK(zeroTKpublic)
    OTKReg(index,zeroTKpublic.x,zeroTKpublic.y,signature)
    data['0TK{}'.format(index)] = zeroTK
    with open("data.json", "w") as json_file:
        json.dump(data, json_file)


#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#get your messages. server will send 1 message from your inbox 
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

#If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())


def to_int(byte):
    return int.from_bytes(byte, byteorder="big")

def KDF_chain(KDF):
    KENC=SHA3_256.new(KDF.to_bytes((KDF.bit_length() + 7) // 8, byteorder="big") + b'LeaveMeAlone').digest()
    KHMAC=SHA3_256.new(KENC + b'GlovesAndSteeringWheel').digest()
    KDF_NEXT=SHA3_256.new(KHMAC + b'YouWillNotHaveTheDrink').digest()
    return to_int(KENC),to_int(KHMAC),to_int(KDF_NEXT)



def Decrypt():
    h,s=signMessage(stuID)
    PseudoSendMsg(h,s)
    stuIDB, otkID,  msgID,  msg , EKx ,EKy =ReqMsg(h,s)
    #Generation of Ks
    EKPoint=Point(EKx,EKy,curve)#EKB.Pub
    T=data["0TK"+otkID]*EKPoint
    U=T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder="big") + T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder="big") + b'MadMadWorld'
    Ks=int.from_bytes(SHA3_256.new(U).digest(), byteorder="big")
    #KDF
    kenc,khmac,kdf=KDF_chain(Ks)
    hmacvalue = HMAC.new(key=khmac.to_bytes((khmac.bit_length() +7)//8, byteorder="big"),msg=msg[1:-32],digestmod=SHA256)
    if(hmacvalue.digest() != msg[-32:]):
        Checker(stuID,stuIDB,msgID,"INVALIDHMAC")
    else:
        counter_obj = Counter.new(
            128,
            initial_value=int.from_bytes(dec_material.iv, byteorder='big'),
            little_endian=False)
        aes = AES.new(kenc, AES.MODE_CTR, counter=counter_obj.new(128))

        # Encrypt and return IV and ciphertext.
        ciphertext = aes.encrypt(me)






if len(sys.argv) < 2:
    print("usage: py .\phase1 <arg>\nargument: -h|--help       display help")
    sys.exit(1)

arg = sys.argv[1]
if arg == "-h" or arg == "--help":
    with open("readme.txt", "r") as f:
        print(f.read())
elif arg == "registerIK":
    Sa = random.randint(1,n-1)
    data['Sa'] = Sa
    with open("data.json", "w") as json_file:
        json.dump(data, json_file)
    Q = Sa * P
    h, s = signMessage(stuID)
    IKRegReq(h, s, Q.x, Q.y)

elif arg == "verifyIK":
    code = int(sys.argv[2])
    IKRegVerify(code)

elif arg == "registerSPK":
    Sp = random.randint(1,n-1)
    data['Sp'] = Sp
    with open("data.json", "w") as json_file:
        json.dump(data, json_file)
    SPKpublic = Sp * P
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
elif arg == "resetSPK":
    h,s = signMessage(stuID)
    ResetSPK(h,s)
elif arg == "genHMAC":
    ServerSPK = Point(data["serverSPKx"], data["serverSPKy"],curve)
    T = Sp * ServerSPK
    U =   T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder="big") + T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder="big") + b'NoNeedToRideAndHide'
    K_HMAC = int.from_bytes(SHA3_256.new(U).digest(), byteorder="big")
    data['K_HMAC'] = K_HMAC
    with open("data.json", "w") as json_file:
        json.dump(data, json_file)
elif arg == "gen0TK":
    for i in range(10):
        generate0TK(i)
elif arg == "reset0TK":
    h,s = signMessage(stuID)
    ResetOTK(h, s)
else:
    print("usage: py .\phase1 <arg>")


