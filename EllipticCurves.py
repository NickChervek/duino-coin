import secrets
from hashlib import sha256
import os
class EllipticCurves:
    Pcurve = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  #Order of the curve (h is 1)
    Acurve = 0
    Bcurve = 7
    INFINITY_POINT = -1
    xPoint = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    yPoint = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    GPoint = (xPoint, yPoint)
    privKey = -1
    publicKey = -1

    def __init__(self):
        self.loadKeys()

    def modInverse(self,a):
        return pow(a, -1, self.Pcurve)

    def equalModP(self,x, y):
        return (x - y) % self.Pcurve == 0

    def reduceModP(self,x):
        return x % self.Pcurve

    def addition(self,p1, p2):

        if p1 == self.INFINITY_POINT:
            return p2
        if p2 == self.INFINITY_POINT:
            return p1

        x1 = p1[0]
        y1 = p1[1]

        x2 = p2[0]
        y2 = p2[1]

        if self.equalModP(x1, x2) and self.equalModP(y1, -y2):
            return self.INFINITY_POINT

        if self.equalModP(x1, x2) and self.equalModP(y1, y2):
            m = self.reduceModP((3 * x1 * x1 + self.Acurve) * self.modInverse(2 * y1))
        else:
            m = self.reduceModP((y1 - y2) * self.modInverse(x1 - x2))

        b = self.reduceModP(y1 - m * x1)
        x3 = self.reduceModP(m * m - x1 - x2)
        y3 = self.reduceModP(-m * x3 - b)

        return (x3, y3)

    def multiply_two(self,GenPoint, times):
        binary_form = str(bin(times)[2:])[::-1]
        result = self.INFINITY_POINT  # The identity element
        addend = GenPoint

        for bit in binary_form:
            if bit == "1":
                result = self.addition(result, addend)
            addend = self.doublePoint(addend)
        return result

    def doublePoint(self,point):
        return self.addition(point, point)

    def sign_transaction(self,message):
        hash = int(sha256(message.encode()).hexdigest(), base=16)
        k = secrets.randbits(256)
        p = self.multiply_two(self.GPoint, k)
        r = p[0] % self.N
        s = ((hash + r * self.privKey) * pow(k, -1, self.N)) % self.N
        return (r, s, hash)

    def verify_transaction(self,messageHash, r, s, public_key):
        sI = pow(s, -1, self.N)
        p_1 = self.multiply_two(self.GPoint, (messageHash * sI) % self.N)
        p_2 = self.multiply_two(public_key, (r * sI) % self.N)
        sum = self.addition(p_1, p_2)
        return sum[0] == r


    def loadKeys(self):
        dir = os.getcwd()
        fileName = "keys.txt"
        pathToFile = os.path.join(dir, fileName)
        print(pathToFile)
        if os.path.exists(pathToFile):
            # Load the keys here...
            print("Debug: Keys exist. Loading keys from file....")

            with open(pathToFile,'r') as f:
                publicKey = f.readline()[7:]
                privateKey = f.readline()[8:]
                self.publicKey = publicKey
                self.privKey = privateKey
                print("Public Key:" + str(publicKey))
                print("Priate Key: " + str(privateKey))
        else:
            print("Debug: Keys do not exist. Generating....")
            with open(pathToFile, 'w') as f:
                privKey = secrets.randbits(256)
                self.privKey = int(privKey)
                publicKey = self.multiply_two(self.GPoint,self.privKey)
                self.publicKey = "04"+ "%064x" % publicKey[0] + "%064x" % publicKey[1]
                f.write("Public: " + str(self.publicKey) + '\n')
                f.write("Private: " + str(hex(self.privKey)))