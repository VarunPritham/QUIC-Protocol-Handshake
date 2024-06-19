
from cryptography.hazmat.backends import default_backend
import math
from binascii import hexlify, unhexlify
import struct
from aioquic.tls import CipherSuite
from scapy.layers.dot11 import algorithms
from scapy.layers.ipsec import Cipher, modes
from scapy.layers.tls.crypto.hkdf import TLS13_HKDF
from scapy.layers.tls.handshake import TLS13Certificate, TLSEncryptedExtensions, \
    TLSCertificateVerify, TLSFinished

CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
}   
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_DRAFT_29 = unhexlify("afbfec289993d24c9e9786f19c6111e04390a899")
INITIAL_SALT_VERSION_1 = unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
SAMPLE_SIZE = 16

class Variable_Integer():
    __slots__ = ["number", "bytes"]

    def __init__(self, val=0):
        if type(val) is int:
            self.number = val
        elif type(val) is bytes:
            self.bytes = val
        elif type(val) is str:
            self.bytes = bytes(val, 'utf-8')

    def encode_integer(self, num=None):
        if num is None:
            num = self.number
        self.number = num

        # two bits are used to encode integer length
        encoded_length_bits = 2
        # We need atleast 1 bit that translate in atleast 1 byte
        # bit_length() returns 0 if the integer is 0
        bit_length = num.bit_length()
        bit_length = max(bit_length, 1)

        byte_length = math.ceil((bit_length + encoded_length_bits) / 8)
        byte_length = max(byte_length, 1)

        encoded_length = math.ceil(math.log(byte_length, 2))
        encoded_num = num | encoded_length << (bit_length - 1)

        bin_num = encoded_num.to_bytes(byte_length, 'big')
        bin_array = bytearray(bin_num)

        # Note that in QUIC1 the encoded length is put in the two most significant bits
        # This will override the first two most valuable bits with the length
        bin_array[0] = bin_array[0] | (encoded_length << 6)

        self.bytes = bytes(bin_array)
        return self.bytes

    def decode(self, data=None):
        if data is None:
            data = self.bytes
        # The length of variable-length integers is encoded in the
        # first two bits of the first byte.
        byte_array = bytearray(data)
        v = byte_array[0]
        prefix = v >> 6
        length = 1 << prefix

        # Once the length is known, remove these bits and read any
        # remaining bytes.
        v = v & 0x3f
        for x in range(1, length):
            v = (v << 8) + byte_array[x]
        self.number = v
        return self.number, length



class Quic_Parser:
    INITIAL_SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
    expected_packet_no = 0
    key_phase = 0
    def __init__(self,payload):
        self.quic_initial_packet_bytes = payload

        self.load_header(self.quic_initial_packet_bytes,1)
        self.get_initial_secret()
        self.header = self.decrypt_header()
        self.load_header(self.header, 2)

    def load_header(self,pkt,take = 1):
        self.packet_type = pkt[0] >> len(pkt) * 8 - 1  # First nibble is packet type
        self.version = struct.unpack("!I", pkt[1:5])[0]  # Next 4 bytes are version

        self.destination_connection_id_length = pkt[5]  # Extract length from lower nibble
        # Extract Connection IDs based on their lengths
        destination_connection_id_start = 6
        destination_connection_id_end = destination_connection_id_start + self.destination_connection_id_length
        self.destination_connection_id = pkt[destination_connection_id_start: destination_connection_id_end]

        source_connection_id_length = pkt[
            destination_connection_id_end]
        source_connection_id_start = destination_connection_id_end + 1
        source_connection_id_end = source_connection_id_start + source_connection_id_length
        self.source_connection_id = pkt[source_connection_id_start: source_connection_id_end]


        print('cids', self.source_connection_id.hex(), self.destination_connection_id.hex())

        # Extract Token Length and Token
        token_length_start = source_connection_id_end
        if pkt[token_length_start] > 0:
            self.token_length = struct.unpack("!H", pkt[
                                                    token_length_start:token_length_start + 2])[0]

            token_start = token_length_start + 2
            token_end = token_start + self.token_length
            self.token = pkt[token_start:token_end]
        else:
            self.token_length = 0
            self.token = None
            token_end = source_connection_id_end + 1

        print('token',self.token,self.token_length)
            # Extract Lengths of Length Fields for Initial Packet Length and Packet Number Length
        length_lengths_start = token_end
        length_length1, length_length2 = struct.unpack('ss',pkt[length_lengths_start:length_lengths_start + 2])

        # Extract Length of Initial Packet Length
        self.initial_packet_length, self.initial_packet_length_length = Variable_Integer(
            length_length1 + length_length2).decode()
        self.initial_packet_length -= 1
        print('init pkt len',self.initial_packet_length)
        # Extract Length of Packet Number Length
        self.packet_number_length = pkt[0] & 0x00

        if take == 1:
            self.encrypted_offset = length_lengths_start + 2
            self.encrypted_payload = pkt[self.encrypted_offset + 1:]
            self.encrypted_header = pkt[:self.encrypted_offset + 1]
        else:
            self.packet_number_length += 1
            packet_number_start = length_lengths_start + 2
            self.packet_number = pkt[packet_number_start:packet_number_start + self.packet_number_length]


    def handshake(self):
        certificate = TLS13Certificate()
        extensions = TLSEncryptedExtensions()
        cert_verify = TLSCertificateVerify()
        finished = TLSFinished()





    def decrypt_header(self):
        PNL = self.packet_number_length + 1

        sample_start = 4 - PNL  # The receiver will assume PNL is 4
        sample = self.encrypted_payload[sample_start: sample_start + 16]
        

        decryptor = Cipher(algorithms.AES(self.header_protection_key),
                           modes.ECB(),
                           backend=default_backend()).encryptor()

        mask = decryptor.update(sample) + decryptor.finalize()
        print('mask', mask)

        decrypted_header = bytearray(self.encrypted_header)

        for i in range(PNL):
            decrypted_header[-PNL + i] ^= mask[i + 1]

        # unmask PNL
        decrypted_header[0] ^= (mask[0] & 0x0f)
        print(decrypted_header)
        return decrypted_header

    def get_initial_secret(self):
        initial_secret = TLS13_HKDF().extract(Quic_Parser.INITIAL_SALT, self.destination_connection_id)
        print('initial secret',initial_secret)

        self.server_initial_secret = TLS13_HKDF().expand_label(initial_secret,
                                                          b"client in", b"", 32)

        # self.server_initial_secret = hkdf_expand_label(algorithm, initial_secret, b"server in", b"", algorithm.digest_size)
        self.key = TLS13_HKDF().expand_label(self.server_initial_secret, b"quic key", b"", 16)
        self.initial_vector = TLS13_HKDF().expand_label(self.server_initial_secret, b"quic iv", b"",
                                       12)
        self.header_protection_key = TLS13_HKDF().expand_label(self.server_initial_secret, b"quic hp", b"",
                                       16)
        print('header protection key',self.key,self.initial_vector,self.header_protection_key)
