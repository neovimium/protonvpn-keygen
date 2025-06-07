import asyncio
import base64
import hashlib
import secrets

class Curve:
    a = -1
    d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
    P = 2**255 - 19
    n = 2**252 + 27742317777372353535851937790883648493
    h = 8
    Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
    Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960

CURVE = Curve()
B32 = 32

def mod(a, b=CURVE.P):
    res = a % b
    return res if res >= 0 else b + res

def invert(number, modulo=CURVE.P):
    if number == 0 or modulo <= 0:
        raise ValueError(f"invert: expected positive integers, got n={number} mod={modulo}")
    a = mod(number, modulo)
    b = modulo
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q = b // a
        r = b % a
        m = x - u * q
        n = y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    if gcd != 1:
        raise ValueError("invert: does not exist")
    return mod(x, modulo)

def bytes_to_number_le(uint8a):
    value = 0
    for i in range(len(uint8a)):
        value += uint8a[i] << (8 * i)
    return value

def is_within_curve_order(num):
    return 0 < num < CURVE.n

def random_private_key():
    for _ in range(1024):
        b32 = secrets.token_bytes(32)
        num = bytes_to_number_le(b32)
        if 1 < num < CURVE.n:
            return b32
    raise RuntimeError("valid private key was not found in 1024 iterations, prng is broken")

async def sha512(message):
    return hashlib.sha512(message).digest()

def encode_private(private_bytes):
    last = B32 - 1
    head = bytearray(private_bytes[:B32])
    head[0] &= 248
    head[last] &= 127
    head[last] |= 64
    return mod(bytes_to_number_le(head), CURVE.n)

class ExtendedPoint:
    def __init__(self, x, y, z, t):
        self.x = x
        self.y = y
        self.z = z
        self.t = t
    
    @classmethod
    def from_affine(cls, p):
        if p.equals(Point.ZERO):
            return ExtendedPoint.ZERO
        return cls(p.x, p.y, 1, mod(p.x * p.y))
    
    def equals(self, other):
        return mod(self.t * other.z) == mod(other.t * self.z)
    
    def double(self):
        X1, Y1, Z1 = self.x, self.y, self.z
        a = CURVE.a
        A = mod(X1**2)
        B = mod(Y1**2)
        C = mod(2 * Z1**2)
        D = mod(a * A)
        E = mod((X1 + Y1)**2 - A - B)
        G = mod(D + B)
        F = mod(G - C)
        H = mod(D - B)
        X3 = mod(E * F)
        Y3 = mod(G * H)
        T3 = mod(E * H)
        Z3 = mod(F * G)
        return ExtendedPoint(X3, Y3, Z3, T3)
    
    def add(self, other):
        X1, Y1, Z1, T1 = self.x, self.y, self.z, self.t
        X2, Y2, Z2, T2 = other.x, other.y, other.z, other.t
        A = mod((Y1 - X1) * (Y2 + X2))
        B = mod((Y1 + X1) * (Y2 - X2))
        F = mod(B - A)
        if F == 0:
            return self.double()
        C = mod(Z1 * 2 * T2)
        D = mod(T1 * 2 * Z2)
        E = mod(D + C)
        G = mod(B + A)
        H = mod(D - C)
        X3 = mod(E * F)
        Y3 = mod(G * H)
        T3 = mod(E * H)
        Z3 = mod(F * G)
        return ExtendedPoint(X3, Y3, Z3, T3)
    
    def multiply_unsafe(self, scalar):
        n = scalar if scalar != 1 else 1
        if n == 1:
            return self
        p = ExtendedPoint.ZERO
        d = self
        while n > 0:
            if n & 1:
                p = p.add(d)
            d = d.double()
            n >>= 1
        return p
    
    def to_affine(self, inv_z=None):
        if inv_z is None:
            inv_z = invert(self.z)
        x = mod(self.x * inv_z)
        y = mod(self.y * inv_z)
        return Point(x, y)

ExtendedPoint.BASE = ExtendedPoint(CURVE.Gx, CURVE.Gy, 1, mod(CURVE.Gx * CURVE.Gy))
ExtendedPoint.ZERO = ExtendedPoint(0, 1, 1, 0)

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def equals(self, other):
        return self.x == other.x and self.y == other.y
    
    def to_raw_bytes(self):
        hex_str = hex(self.y)[2:]
        if len(hex_str) & 1:
            hex_str = f"0{hex_str}"
        u8 = bytearray(B32)
        for i in range(len(hex_str) - 2, -1, -2):
            if i >= 0:
                j = (len(hex_str) - 2 - i) // 2
                if j < B32:
                    u8[j] = int(hex_str[i:i+2], 16)
        mask = 0x80 if self.x & 1 else 0
        u8[B32 - 1] |= mask
        return bytes(u8)
    
    def multiply(self, scalar):
        return ExtendedPoint.from_affine(self).multiply_unsafe(scalar).to_affine()

    @staticmethod
    def from_affine(p):
        if p.equals(Point.ZERO):
            return ExtendedPoint.ZERO
        return ExtendedPoint(p.x, p.y, 1, mod(p.x * p.y))

Point.BASE = Point(CURVE.Gx, CURVE.Gy)
Point.ZERO = Point(0, 1)

async def get_public_key(private_key):
    priv_bytes = await sha512(private_key)
    scalar = encode_private(priv_bytes)
    key = Point.BASE.multiply(scalar)
    return key.to_raw_bytes()

async def ed25519_to_x25519(ed25519_private_b64):
    ed25519_private_bytes = base64.b64decode(ed25519_private_b64)
    sha512_hash = await sha512(ed25519_private_bytes)
    x25519_private = bytearray(sha512_hash[:32])
    x25519_private[0] &= 0xf8
    x25519_private[31] &= 0x7f
    x25519_private[31] |= 0x40
    return base64.b64encode(x25519_private).decode('ascii')

async def generate_keys():
    ed25519_private = random_private_key()
    ed25519_public = await get_public_key(ed25519_private)
    ed25519_private_b64 = base64.b64encode(ed25519_private).decode('ascii')
    ed25519_public_b64 = base64.b64encode(ed25519_public).decode('ascii')
    x25519_private_b64 = await ed25519_to_x25519(ed25519_private_b64)
    
    return {
        'ed25519_private': ed25519_private_b64,
        'ed25519_public': ed25519_public_b64,
        'x25519_private': x25519_private_b64
    }

async def main():
    keys = await generate_keys()
    print("Ed25519 Private (Unused):", keys['ed25519_private'])
    print("Ed25519 Public (API):", keys['ed25519_public'])
    print("X25519 Private (WG):", keys['x25519_private'])

if __name__ == "__main__":
    asyncio.run(main())
