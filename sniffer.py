import socket
import struct
import textwrap



def main():
    HOST = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((HOST,0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        dadosCru, endereco = conn.recvfrom(65536)
        macDestino, macFonte, protoEthernet, dados = quadroEthernet(dadosCru)
        print('\nQuadro Ethernet:')
        print('Destino: {}, Fonte: {}, Protocolo: {}'.format(macDestino,macFonte,protoEthernet))

def quadroEthernet(dados):
    macDestino, macFonte, proto = struct.unpack('! 6s 6s H', dados[:14])
    return coletaEnderecoMac(macDestino), coletaEnderecoMac(macFonte), socket.htons(proto), dados[:14]

def coletaEnderecoMac(enderecoBytes):
    stringBytes = map('{:02X}'.format, enderecoBytes)
    return':'.join(stringBytes)

main()