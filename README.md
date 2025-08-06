# TLS Flag Hunt Challenge 🔍🔒

A forensic challenge that involves decrypting TLS traffic to find a hidden flag in the format FLAG{...}.

## Challenge Description
Participants are given a PCAP file containing TLS-encrypted traffic. The flag (in FLAG{...} format) is hidden in an encrypted HTTP session, and they must use the provided TLS key log file to decrypt it.

## Files Provided
- real_tls_flag_hunt.pcap - Network capture containing TLS-encrypted traffic
- tls_decryption.key - TLS key log file for decryption
- server.crt - Server certificate (optional for analysis)

## Challenge Setup
```bash
# Install required tools
sudo apt install wireshark tshark

# Or on macOS
brew install wireshark
```

## Hints 
- The flag is in standard CTF format: FLAG{...}
- You'll need to decrypt TLS traffic using the key log file
- Look for HTTP application data containing the flag pattern

## License 📜

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. ⚖️

Happy Hacking! 🚀
