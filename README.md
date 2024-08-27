Updated from https://wifininjas.net/2019/08/23/wn-blog-012-can-you-crack-802-1x-wpa2-enterprise-wireless-data/

# Building

## Dependencies

```bash
$ sudo apt-get install libssl-dev # needed by : #include <openssl/evp.h>
```

## Build

```bash
$ gcc -o PMKextract PMKextract.cpp -lcrypto
```
# Use it

```bash
$ ./PMKextract 
Usage: ./PMKextract secret authenticator recv-key
```

```bash
$ ./PMKextract 'january' '00:0d:42:73:f6:19:5c:d3:88:73:cf:b3:2c:76:5d:16' 'cf:6f:b5:06:da:57:b1:9c:e4:6d:76:af:93:$1:59:7e:2c:f8:cd:79:c6:2b:e1:a5:4f:ab:28:bd:ed:d3:81:d3:a9:57:dd:74:f8:d1:41:b8:ec:50:ea:d7:27:75:85:d3:1e:d3'
PMK is:
e70d0f9bb569eecef484189a76f6d915c5286493f69751d0a2115b6dedff78dd
```
