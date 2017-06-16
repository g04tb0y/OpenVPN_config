# OpenVPN Secure Configuration Template
This is a simple way to create your own OpenVPN service. It is intended for a very small number of clients, but can be easly tweeked for larger client pool. It's fully tested, so do not mess with configuration if you want the VPN work out-of-the-box!

# Async key pair generation
The detailed command will not be covered in this guide, for now.
I strongly suggest to use [easy-rsa](https://github.com/OpenVPN/easy-rsa) to generate and manage key pair.

Because you have to keep the server private key on the server, it's best practice to seprate the key pair of the server from the CA's key pair.

Follow this step:
1. Generate Certification authority key pair and self-signed certificate.
2. Generate Server key pair and sign the certificate with CA private key
3. Generate Client key pair and sign the certificate with CA private key



### Chain of trust
This step will resulting in a pretty basic a chain of trust:
```         
              
              <CA>
               ||
               \/
      +-----+-----+-----+--
      |     |     |     |
      |     |     |     |
     SRV   CL1   CL2   CL3
```


A snip from official how-to:
```
Both server and client will authenticate the other by first verifying that the presented certificate was signed by the master certificate authority (CA), and then by testing information in the now-authenticated certificate header, such as the certificate common name or certificate type (client or server).

This security model has a number of desirable features from the VPN perspective:

    The server only needs its own certificate/key -- it doesn't need to know the individual certificates of every client which might possibly connect to it.
    The server will only accept clients whose certificates were signed by the master CA certificate (which we will generate below). And because the server can perform this signature verification without needing access to the CA private key itself, it is possible for the CA key (the most sensitive key in the entire PKI) to reside on a completely different machine, even one without a network connection.
    If a private key is compromised, it can be disabled by adding its certificate to a CRL (certificate revocation list). The CRL allows compromised certificates to be selectively rejected without requiring that the entire PKI be rebuilt.
    The server can enforce client-specific access rights based on embedded certificate fields, such as the Common Name.

Note that the server and client clocks need to be roughly in sync or certificates might not work properly.
```


# Server Routing Settings

Enable IP forwarding:
```
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
Allow TCP connection to local port 443 (or your choosen openvpn server port)
```
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

Allow TUN interface connections to be forwarded through other interfaces
```
sudo iptables -A FORWARD -i eth0 -o tun1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tun1 -o eth0 -j ACCEPT
```

NAT the VPN client traffic to the internet
```
sudo iptables -t nat -A POSTROUTING -s 10.4.0.1/2 -o eth0 -j MASQUERADE
```


# Client configuration
```
#
# OpenVPN client side config
#

# Client network protocol
proto tcp-client
client

# OpenVPN server address
remote [ServerDomainName|IP-Address]
# OpenVPN server port
port 443
# Http proxy config
# http-proxy [address] [6128]
# Local virtual interface
dev tun0


ifconfig 10.4.0.2 10.4.0.1
# Enable TLS and assume client role during TLS handshake. 
tls-client

persist-tun
persist-key

# Do not bind to local address and port.
nobind

# Use fast LZO compression
comp-lzo
resolv-retry 10
# Verbosity level
verb 3

# HMAC key direction (server is 0)
key-direction 1

# remote-cert-ku f8 # in case of certificate key usage error

# Data encryption cipher
cipher AES-256-CBC
# Authentication
auth SHA512

# Specify TLS cipher to avoid weak ciphers: KEY_EXCHANGE-AUTHENTICATION-HASHES (Must be kept up to date)
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA


<key>
-----BEGIN ENCRYPTED PRIVATE KEY-----
mFMLzLUyBmqEv4SLg7bLmb0NdVBa+WW/7vjGppe8GSiAE5CPDlqHNopdGT8RkZWx
...
...
-----END ENCRYPTED PRIVATE KEY-----
</key>

<cert>
-----BEGIN CERTIFICATE-----
coBBfzi3/bdJhk5tuXnY+9GKgHyCsr5W3E+wrQEjykHDSaWjMBMGA1UdJQQMMAoG
...
...insert
-----END CERTIFICATE-----
</cert>


<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
7030190a482df9bbcc2719e94f9d8715
...insert openvpn key
...
-----END OpenVPN Static key V1-----
</tls-auth>
<ca>
-----BEGIN CERTIFICATE-----
C290xFgKuOC+RwjcGLE11FPKHmAbo4IiMSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
...insert CA certificate
...
-----END CERTIFICATE-----
</ca>

```


# Server configuration
```
#
# OpenVPN server side config
#

# Listner port
port 443
# Network protocol
proto tcp-server
# Virtual interface
dev tun1

# Bound the server on any interface
local 0.0.0.0 443

# Server gateway
ifconfig 10.4.0.1 10.4.0.2
# Address length-mask
server 10.4.0.0 255.255.255.0
# Don't close and reopen TUN device after SIGUSR1 signal
persist-tun
# Don't re-read the key after SIGUSR1 signal
persist-key
# Redirect to the serve gateway
push "redirect-gateway"


# Try to override DNS. It's not an high priority setting, could be easily overrided.
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

#ifconfig-pool-persist ipp.txt 

# Log file-path
status /var/run/openvpn/server-tcp.log
# Verbosity level
verb 3


# Diffie-Hellman key-exchange 4096 bit
dh /etc/openvpn/pki/dh4096.pem
# Certification Authority certificate
ca /etc/openvpn/pki/ca.crt
# Server certificate
cert /etc/openvpn/pki/aws-vpn-srv.crt
# Server private key
key /etc/openvpn/pki/AWS_VPN_SRV.key

# Authentication
auth SHA512
# Enable TLS and assume server role during TLS handshake.
tls-server
# Add an additional layer of HMAC authentication on top of the TLS control channel to protect against DoS attacks and set key direction to 0
tls-auth /etc/openvpn/pki2/ovpn.key 0

# Data encryption cipher (Must be kept up to date)
cipher AES-256-CBC

# Specify TLS cipher to avoid weak ciphers: KEY_EXCHANGE-AUTHENTICATION-HASHES (Must be kept up to date)
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-256-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA:TLS-DHE-RSA-WITH-AES-128-CBC-SHA:TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA
# add "tls-version-min 1.2"(check the current standard) to avoid downgrade if your openvpn version support it (by the way, kept always up to date)

# Drop privilege to nobody user
user nobody
group nobody

# Max client connected simultaneously
max-clients 10

# Keep alive, ping and ping-restart macro
keepalive 60 300

# Use fast LZO compression
comp-lzo

```

# Security Enanchement

If you want to improve cryptography and your server and openvpn client support it, you could use ECDHE (Elliptic curve Diffie–Hellman) for key exchange + RSA for authentication + AES-256-GCM-SHA384 (authenticated by Galois/Counter Mode with SHA384) for the handshake:
```
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
```

# Common Issues
it happens sometime that client network configuration gone wild for astral/arcanum reasons...so here some useful commands:

Default routing is not set correctly. Reset default routing and add a new one:
```
sudo route delete default
```
Check the correct destination using ```ifconfig```
```
--- snip ---
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.4.0.6  netmask 255.255.255.255  **destination 10.4.0.5**
...
```
and specify the openvpn virtual interface:
```
sudo ip route add default via 10.4.0.5 dev tun0

```
If you are able to ping 8.8.8.8 but can't resolve google.com, change the DNS setting, for example with the google DNS:
```
sudo echo "nameserver 8.8.8.8" > resolv.conf
sudo echo "nameserver 8.8.4.4" >> resolv.conf
sudo mv resolv.conf /etc/resolv.conf

``` 

# Resources

[openvpn.net - How To](https://openvpn.net/index.php/open-source/documentation/howto.html)

[Recommendation for Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)

[Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc7919)