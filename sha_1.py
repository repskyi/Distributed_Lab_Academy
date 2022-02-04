from struct import pack, unpack

def GetSHA1Hash(message):
    """ Returns SHA1 string"""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0  #variables initialization

    def rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    def padding(message):
        data = bytes(message, 'utf-8') # переводимо стрічку у байти
        padding = b'\x80' + b'\x00' * (63 - (len(data) + 8) % 64)
        padded_data = data + padding + pack('>Q', 8 * len(data))
        return padded_data

    padded_data = padding(message)

    chunk = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in chunk:
        w = list(unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):  # до 80 бо python верхня межа не враховується
            w[i] = rotate((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1) # wi модифікований елемент вхідного повідомлення (4 байт)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for i in range(0, 80):
            if 0 <= i < 20: 
                f = (b & c) | ((~b) & d) # f змінна функція (змінюється кожні 20 циклів);
                k = 0x5A827999 #K – константи; (ніби солі)
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotate(a, 5) + f + e + k + w[i]) % (2 ** 32)

            e = d
            d = c
            c = rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) % (2 ** 32)
        h1 = (h1 + b) % (2 ** 32)
        h2 = (h2 + c) % (2 ** 32)
        h3 = (h3 + d) % (2 ** 32)
        h4 = (h4 + e) % (2 ** 32)

        hash = '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4) 
    
    return hash

message = input("Enter the string: ")
print(GetSHA1Hash(message))