import secrets
import socket
from QuicParser import Quic_Parser
from Quic_Packet import QUIC
import asyncio
import aioquic


def recv():
    print("receiving")
    server_ip = '127.0.0.1'
    server_port = 50508
    Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    Socket.bind((server_ip, server_port))
    response, addr = Socket.recvfrom(1024)
    quic_packet = Quic_Parser(response)
    max_ack = 0
    packet_no = int.from_bytes(quic_packet.packet_number,byteorder='big')
    max_ack = max(max_ack,packet_no)
    DCID = bytes.fromhex(secrets.token_hex(8))
    SCID = bytes.fromhex(secrets.token_hex(8))

    initial_server = QUIC(SCID,DCID,add_crypto=True,add_ack=True,largest_ack=max_ack,client=False).packet
    handshake_packet = QUIC(SCID, DCID, pkt_type='HANDSHAKE').packet
    Socket.sendto(initial_server,addr)
    
    Socket.sendto(handshake_packet, addr)


def main():
    recv()


if __name__ == '__main__':
    main()

