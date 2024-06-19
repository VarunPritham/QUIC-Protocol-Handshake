
from QuicParser import Quic_Parser
import secrets
import socket
from Quic_Packet import QUIC

def send():
        print("sending")
        DCID = bytes.fromhex(secrets.token_hex(8))
        SCID = bytes.fromhex(secrets.token_hex(8))
        print(type(DCID),DCID,SCID)
        initial_packet = QUIC(SCID,DCID,pkt_type='INITIAL',add_crypto=True).packet
        print('final packet to be sent ',initial_packet)
        client = '127.0.0.1'
        client_port = 50505
        server_ip = '127.0.0.1'
        server_port = 50508
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((client, client_port))
        s.sendto(initial_packet, ('127.0.0.1', server_port))
        response,addr=s.recvfrom(1024)
        initial_response = Quic_Parser(response)
        response,addr=s.recvfrom(1024)
        handshake_response = Quic_Parser(response)



send()