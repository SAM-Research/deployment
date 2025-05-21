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

1. Create a JSON config file, in the format below:

```jsonc
{
  "samnet": {
    "linkSecret": "linktest", // Secret to use when provsioning devices
    "logging": "info", // Logging level (optional)
    "provisionTimeout": 600, // Time in seconds before a device link token becomes invalid
    "deniableRatio": 1.0, // Deniable ratio (q)
    "bufferSize": 10, // Size of buffers used internally by both the SAM Server and the DenIM-SAM-Proxy
    "expose": 4443, // Port used on your host machine (optional, only if you want to access the server from outside the docker network)
    "inmemory": false // Use inmemory sqlite for clients
    "tls": {
      // TLS configuration (optional)
      "mtls": true, // Internal communication on the network happens over mtls
      "config": {
        // fields for openssl
        "C": "DK",
        "ST": "Nordjylland",
        "L": "Aalborg",
        "O": "SAM-Research",
        "OU": "IT",
        "CN": "localhost"
      }
    }
  },
  // https://github.com/SAM-Research/sam-dispatch/blob/main/README.md
  "samDispatch": {
    "name": "Example Scenario",
    "type": "denim",
    // address is set automaticly
    "clients": 1,
    "groups": [1],
    "tickMillis": 1000,
    "durationTicks": 500,
    "messageSizeRange": [200, 500],
    "denimProbability": 1,
    "sendRateRange": [1, 5],
    "report": "report.json",
    "replyRateRange": [1, 1],
    "replyProbability": [0.95, 0.95],
    "staleReplyRange": [100, 100],
    // additional field to expose dispatch to host
    "expose": 8080
  }
}
```

2. install docker and docker compose https://www.docker.com/
3. install tshark https://www.wireshark.org/docs/man-pages/tshark.html
4. install dependencies `pip install -r requirements.txt`
5. run `python ./setup/setup.py <PROJECT_NAME> <PATH_TO_JSON_CONFIG>`
6. run `docker compose up`
