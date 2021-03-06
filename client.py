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
    message = zeroTKpublic.x.to_bytes(
        (zeroTKpublic.x.bit_length() + 7) // 8, byteorder="big"
    ) + zeroTKpublic.y.to_bytes((zeroTKpublic.y.bit_length() + 7) // 8, byteorder="big")
    hmac = HMAC.new(
        key=K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder="big"),
        msg=message,
        digestmod=SHA256,
    )
    return hmac.hexdigest()


def generate0TK(index):
    zeroTK = random.randint(1, n - 1)
    zeroTKpublic = zeroTK * P
    signature = sign0TK(zeroTKpublic)
    OTKReg(index, zeroTKpublic.x, zeroTKpublic.y, signature)
    data["0TK{}".format(index)] = zeroTK
    data["keyAmount"] += 1
    with open("data.json", "w") as json_file:
        json.dump(data, json_file)


# Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "PseudoSendMsg"), json=mes)
    print(response.json())


# get your messages. server will send 1 message from your inbox
def ReqMsg(h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.get("{}/{}".format(API_URL, "ReqMsg"), json=mes)
    print(response.json())
    if (response.ok) == True:
        res = response.json()
        return (
            res["IDB"],
            res["OTKID"],
            res["MSGID"],
            res["MSG"],
            res["EK.X"],
            res["EK.Y"],
        )


def PseudoSendMsgPH3(h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())


def SendMsg(idA, idB, otkid, msgid, msg, ekx, eky):
    mes = {
        "IDA": idA,
        "IDB": idB,
        "OTKID": int(otkid),
        "MSGID": msgid,
        "MSG": msg,
        "EK.X": ekx,
        "EK.Y": eky,
    }
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "SendMSG"), json=mes)
    print(response.json())


def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {"IDA": stuID, "IDB": stuIDB, "S": s, "H": h}
    print("Requesting party B's OTK ...")
    response = requests.get("{}/{}".format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json())
    if (response.ok) == True:
        print(response.json())
        res = response.json()
        return res["KEYID"], res["OTK.X"], res["OTK.Y"]
    else:
        return -1, 0, 0


def Status(stuID, h, s):
    mes = {"ID": stuID, "H": h, "S": s}
    print("Sending message is: ", mes)
    response = requests.get("{}/{}".format(API_URL, "Status"), json=mes)
    print(response.json())
    if response.ok == True:
        res = response.json()
        return res["numMSG"], res["numOTK"], res["StatusMSG"]


# If you decrypted the message, send back the plaintext for grading
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {"IDA": stuID, "IDB": stuIDB, "MSGID": msgID, "DECMSG": decmsg}
    print("Sending message is: ", mes)
    response = requests.put("{}/{}".format(API_URL, "Checker"), json=mes)
    print(response.json())


def byteToInt(byte):
    return int.from_bytes(byte, byteorder="big")


def intToByte(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder="big")


def KDF_chain(KDF):
    KENC = SHA3_256.new(KDF + b"LeaveMeAlone").digest()
    KHMAC = SHA3_256.new(KENC + b"GlovesAndSteeringWheel").digest()
    KDF_NEXT = SHA3_256.new(KHMAC + b"YouWillNotHaveTheDrink").digest()
    return KENC, KHMAC, KDF_NEXT


def DecryptPseudoMessages():
    h, s = signMessage(stuID)
    PseudoSendMsg(h, s)
    stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
    # Generation of Ks
    EKPoint = Point(EKx, EKy, curve)  # EKB.Pub
    T = data["0TK" + str(otkID)] * EKPoint
    U = intToByte(T.x) + intToByte(T.y) + b"MadMadWorld"
    Ks = SHA3_256.new(U).digest()
    kdf = Ks
    kenc, khmac, kdf = KDF_chain(kdf)
    plaintext = DecryptMessage(kenc, khmac, msg)
    Checker(stuID, stuIDB, msgID, plaintext)
    for i in range(4):
        stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
        kenc, khmac, kdf = KDF_chain(kdf)
        plaintext = DecryptMessage(kenc, khmac, msg)
        Checker(stuID, stuIDB, msgID, plaintext)


def DecryptMessage(kenc, khmac, msg):
    msg = intToByte(msg)
    nonce = msg[:8]
    hmac = msg[-32:]
    msg = msg[8:-32]
    hmacvalue = HMAC.new(
        key=khmac,
        msg=msg,
        digestmod=SHA256,
    )
    if hmacvalue.digest() != hmac:
        return "INVALIDHMAC"
    else:
        aes = AES.new(kenc, AES.MODE_CTR, nonce=nonce)
        plaintext = aes.decrypt(msg).decode("utf-8")
        return plaintext


def EncrpytMessage(kenc, khmac, msg):
    cipher = AES.new(kenc, AES.MODE_CTR)
    nonce = cipher.nonce
    ctext = cipher.encrypt(msg)
    hmac = HMAC.new(
        key=khmac,
        msg=ctext,
        digestmod=SHA256,
    )
    return nonce + ctext + hmac.digest()


def SendMessageBlock(stuIDB, messages):
    h, s = signMessage(stuIDB)
    id, OTKx, OTKy = reqOTKB(stuID, stuIDB, h, s)
    zeroTK = random.randint(1, n - 1)
    zeroTKpublic = zeroTK * P
    OTK = Point(OTKx, OTKy, curve)
    T = zeroTK * OTK
    U = intToByte(T.x) + intToByte(T.y) + b"MadMadWorld"
    Ks = SHA3_256.new(U).digest()
    kdf = Ks
    for i in range(len(messages)):
        enc, hmac, kdf = KDF_chain(kdf)
        encmessage = EncrpytMessage(enc, hmac, messages[i])
        SendMsg(
            stuID, stuIDB, id, i, byteToInt(encmessage), zeroTKpublic.x, zeroTKpublic.y
        )


def SendPseudoMessages():
    h, s = signMessage(stuID)
    PseudoSendMsgPH3(h, s)
    messages = []
    stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
    # Generation of Ks
    EKPoint = Point(EKx, EKy, curve)  # EKB.Pub
    T = data["0TK" + str(otkID)] * EKPoint
    U = intToByte(T.x) + intToByte(T.y) + b"MadMadWorld"
    Ks = SHA3_256.new(U).digest()
    kdf = Ks
    kenc, khmac, kdf = KDF_chain(kdf)
    plaintext = DecryptMessage(kenc, khmac, msg).encode("utf-8")
    messages.append(plaintext)
    for i in range(4):
        stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
        kenc, khmac, kdf = KDF_chain(kdf)
        plaintext = DecryptMessage(kenc, khmac, msg).encode("utf-8")
        messages.append(plaintext)

    SendMessageBlock(18007, messages)


if len(sys.argv) < 2:
    h, s = signMessage(stuID)
    numMSG, numOTK, stat = Status(stuID, h, s)
    keyAmount = data["keyAmount"]
    for i in range(10 - numOTK):
        generate0TK(keyAmount + i)
    SendPseudoMessages()
else:
    arg = sys.argv[1]
    if arg == "-h" or arg == "--help":
        with open("readme.txt", "r") as f:
            print(f.read())
    elif arg == "registerIK":
        Sa = random.randint(1, n - 1)
        data["Sa"] = Sa
        with open("data.json", "w") as json_file:
            json.dump(data, json_file)
        Q = Sa * P
        h, s = signMessage(stuID)
        IKRegReq(h, s, Q.x, Q.y)

    elif arg == "verifyIK":
        code = int(sys.argv[2])
        IKRegVerify(code)

    elif arg == "registerSPK":
        Sp = random.randint(1, n - 1)
        data["Sp"] = Sp
        with open("data.json", "w") as json_file:
            json.dump(data, json_file)
        SPKpublic = Sp * P
        xBytes = SPKpublic.x.to_bytes(
            (SPKpublic.x.bit_length() + 7) // 8, byteorder="big"
        )
        yBytes = SPKpublic.y.to_bytes(
            (SPKpublic.y.bit_length() + 7) // 8, byteorder="big"
        )
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
        h, s = signMessage(stuID)
        ResetSPK(h, s)
    elif arg == "genHMAC":
        ServerSPK = Point(data["serverSPKx"], data["serverSPKy"], curve)
        T = Sp * ServerSPK
        U = (
            T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder="big")
            + T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder="big")
            + b"NoNeedToRideAndHide"
        )
        K_HMAC = int.from_bytes(SHA3_256.new(U).digest(), byteorder="big")
        data["K_HMAC"] = K_HMAC
        with open("data.json", "w") as json_file:
            json.dump(data, json_file)
    elif arg == "gen0TK":
        for i in range(10):
            generate0TK(i)
    elif arg == "reset0TK":
        h, s = signMessage(stuID)
        ResetOTK(h, s)
    elif arg == "getMessages":
        h, s = signMessage(stuID)
        numMSG, numOTK, stat = Status(stuID, h, s)
        keyAmount = data["keyAmount"]
        for i in range(10 - numOTK):
            generate0TK(keyAmount + i)
        if numMSG > 0:
            stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
            EKPoint = Point(EKx, EKy, curve)  # EKB.Pub
            T = data["0TK" + str(otkID)] * EKPoint
            U = intToByte(T.x) + intToByte(T.y) + b"MadMadWorld"
            Ks = SHA3_256.new(U).digest()
            kdf = Ks
            kenc, khmac, kdf = KDF_chain(kdf)
            plaintext = DecryptMessage(kenc, khmac, msg)
            print("Student with ID {} sent these messages:\n".format(stuIDB))
            print(plaintext)
            for i in range(numMSG - 1):
                stuIDB, otkID, msgID, msg, EKx, EKy = ReqMsg(h, s)
                kenc, khmac, kdf = KDF_chain(kdf)
                plaintext = DecryptMessage(kenc, khmac, msg)
                print(plaintext)
    elif arg == "sendMessages":
        stuIDB = int(input("Enter StudentID you want to send messages: "))
        messages = []
        message = input("Enter Message: ")
        while message != "":
            messages.append(message.encode("utf-8"))
            message = input("Enter Message: ")
        SendMessageBlock(stuIDB, messages)
    else:
        print("usage: py .\phase1 <arg>")
