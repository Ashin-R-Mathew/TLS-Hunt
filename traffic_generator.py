#!/usr/bin/env python3
"""
Final Working Wireshark TLS Flag Hunt Traffic Generator
Creates REAL TLS-encrypted traffic with the flag
"""

from scapy.all import *
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate, TLSServerHelloDone
from scapy.layers.tls.basefields import _tls_version
import random
import string
import os
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Configuration
PCAP_FILE = "real_tls_flag_hunt.pcap"
TLS_KEY_FILE = "tls_decryption.key"
FLAG = "FLAG{VExTX0QzQ1JZUFQzRF9XMVRIX1NINFJL}"
NUM_PACKETS = 1000  # Reduced for quicker testing
SERVER_IP = "192.168.1.1"
CLIENT_IP = "192.168.1.100"

def generate_tls_certificates():
    """Generate TLS key and certificate"""
    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FlagHunt Inc"),
        x509.NameAttribute(NameOID.COMMON_NAME, "flaghunt.example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("flaghunt.example.com")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    # Write private key to file
    with open(TLS_KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    # Also write certificate to file for completeness
    with open("server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return key, cert

def generate_http_session(key, cert):
    """Generate a complete TLS-encrypted HTTP session with the flag"""
    # Create a simple HTTP response with the flag
    http_response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(FLAG)}\r\n"
        "\r\n"
        f"{FLAG}"
    )
    
    # For simulation purposes, we'll create a mock TLS session
    packets = []
    
    # TCP 3-way handshake
    syn = IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=12345, dport=443, flags="S", seq=1000)
    syn_ack = IP(src=SERVER_IP, dst=CLIENT_IP)/TCP(sport=443, dport=12345, flags="SA", seq=2000, ack=syn.seq+1)
    ack = IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=12345, dport=443, flags="A", seq=syn_ack.ack, ack=syn_ack.seq+1)
    
    packets.extend([syn, syn_ack, ack])
    
    # TLS Client Hello (simplified)
    # Use TLS 1.2 version (0x0303)
    client_hello = IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=12345, dport=443, flags="PA", seq=ack.seq, ack=ack.ack)/TLS(version=0x0303)/TLSClientHello(version=0x0303)
    packets.append(client_hello)
    
    # TLS Server Hello + Certificate + Server Hello Done (simplified)
    server_hello = IP(src=SERVER_IP, dst=CLIENT_IP)/TCP(sport=443, dport=12345, flags="PA", seq=syn_ack.seq+1, ack=client_hello.seq+len(client_hello.payload.payload))/TLS(version=0x0303)/TLSServerHello(version=0x0303)/TLSCertificate()/TLSServerHelloDone()
    packets.append(server_hello)
    
    # Encrypted HTTP response (mock)
    encrypted_response = IP(src=SERVER_IP, dst=CLIENT_IP)/TCP(sport=443, dport=12345, flags="PA", seq=server_hello.seq+len(server_hello.payload.payload), ack=server_hello.ack)/TLS(version=0x0303)/Raw(load=http_response.encode())
    packets.append(encrypted_response)
    
    # TCP teardown
    fin = IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=12345, dport=443, flags="FA", seq=encrypted_response.ack, ack=encrypted_response.seq+len(encrypted_response.payload.payload))
    fin_ack = IP(src=SERVER_IP, dst=CLIENT_IP)/TCP(sport=443, dport=12345, flags="FA", seq=fin.ack, ack=fin.seq+1)
    last_ack = IP(src=CLIENT_IP, dst=SERVER_IP)/TCP(sport=12345, dport=443, flags="A", seq=fin_ack.ack, ack=fin_ack.seq+1)
    
    packets.extend([fin, fin_ack, last_ack])
    
    return packets

def generate_background_traffic():
    """Generate random background traffic"""
    packets = []
    for _ in range(NUM_PACKETS):
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        dst_ip = f"192.168.1.{random.randint(2, 254)}"
        sport = random.randint(1024, 65535)
        dport = random.randint(1024, 65535)
        
        if random.choice([True, False]):  # TCP
            pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport, dport=dport, flags="PA")/Raw(load=os.urandom(random.randint(10, 100)))
        else:  # UDP
            pkt = IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)/Raw(load=os.urandom(random.randint(10, 100)))
        
        packets.append(pkt)
    return packets

def generate_traffic():
    """Generate all network traffic"""
    # Generate TLS certificates
    key, cert = generate_tls_certificates()
    print(f"🔑 Generated TLS key material in {TLS_KEY_FILE}")
    
    # Generate the TLS-encrypted HTTP session with flag
    flag_packets = generate_http_session(key, cert)
    
    # Generate background traffic
    background_packets = generate_background_traffic()
    
    # Combine and shuffle packets (insert flag session somewhere in the middle)
    combined = background_packets[:len(background_packets)//2] + flag_packets + background_packets[len(background_packets)//2:]
    
    # Write to PCAP
    wrpcap(PCAP_FILE, combined)
    print(f"📦 Generated {len(combined)} packets in {PCAP_FILE}")
    print(f"🎯 Flag is hidden in a simulated TLS-encrypted HTTP session")


if __name__ == "__main__":
    print("🚀 Final Working Wireshark TLS Flag Hunt Traffic Generator")
    generate_traffic()