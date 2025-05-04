# DenIM SAM Docker Network

This repo contains a script to generate docker compose setup for denim-on-sam.

The generated project contains:

1. Private Network:
   1. SAM Server
   2. DenIM Proxy
   3. Database
   4. Reverse Proxy Gateway exposed to default or host
2. tcpdump on the traffic to and from the gateway
3. SAM Dispatcher for automated test clients

The project can be setup so client and gateway communicates with TLS as well as the internal services.
The internal services can also be setup to use mTLS.

## Usage

1. Create a `.cnf` file for the tls configuration (optional)

```conf
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = req_distinguished_name
x509_extensions    = v3_req

[ req_distinguished_name ]
C = DK
ST = Nordjylland
L = Aalborg
O = SAM
OU = IT
CN = localhost

[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectAltName = @alt_names

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = sam_server
IP.1 = 127.0.0.1
```

2. Create a JSON config file, in the format below:

```jsonc
{
  "samnet": {
    "linkSecret": "linktest", // Secret to use when provsioning devices
    "logging": "info", // Logging level (optional)
    "provisionTimeout": 600, // Time in seconds before a device link token becomes invalid
    "deniableRatio": 1.0, // Deniable ratio (q)
    "bufferSize": 10, // Size of buffers used internally by both the SAM Server and the DenIM-SAM-Proxy
    "expose": 4443, // Port used on your host machine (optional, only if you want to access the server from outside the docker network)
    "tls": {
      // TLS configuration (optional)
      "mtls": true, // Internal communication on the network happens over mtls
      "config": "cert.cnf" // Previously created conf file
    }
  },
  // https://github.com/SAM-Research/sam-dispatch/blob/main/README.md
  "samDispatch": {
    "name": "Example Scenario",
    // address is set automaticly
    "clients": 1,
    "groups": [1],
    "tickMillis": 1000,
    "durationTicks": 500,
    "messageSizeRange": [200, 500],
    "denimProbability": 1,
    "sendRateRange": [1, 5],
    "startEpoch": 10,
    "report": "report.json"
  }
}
```

3. run `python ./setup/setup.py <PROJECT_NAME> <PATH_TO_JSON_CONFIG>`
4. run `docker compose up`
