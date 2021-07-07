# danecert
Simple way to generate a self-signed certificate and a TLSA record for DANE clients.


## Usage

```bash
$ danecert example.com
Generated self-signed certificate: cert.pem, cert.key
TLSA Record data: 3 1 1 deea7e08e8374102c61c047c5c5512d91272a762890defd753cc8202116fb4e2
```

You can use the certificate as you normally would in your web server, and add the TLSA record to your nameserver.

## Build

```bash
$ git clone https://github.com/buffrr/danecert
$ cd danecert && go build
```

## License

MIT
