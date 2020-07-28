# KerberosServerTest
sample program to demonstrate client, server (TCP Echo Server) authenticating on the kerberos. The only dependecy is Kerby Simple KDC server (a light weight framework to test kerberos locally)
### Steps to build
```kubernetes helm
mvn clean package
```

### How to Run
```kubernetes helm
Client needs KDC Server up and running
start Kerby sample KDC Server
Start Kerberos TCP Server
Start Kerberos TCP Client
```
for some reason Server is not able to read the default keytab correctly and you might see the EOF exception while token exchange,
to avoid such issue please add "default_keytab_name = service.keytab" and restart the Server e.g.

```kubernetes helm
[libdefaults]
    kdc_realm = EXAMPLE.COM
    default_realm = EXAMPLE.COM
    udp_preference_limit = 1
    kdc_tcp_port = 10088
    #_KDC_UDP_PORT_
    default_keytab_name = service.keytab

[realms]
    EXAMPLE.COM = {
        kdc = localhost:10088
    }
```
