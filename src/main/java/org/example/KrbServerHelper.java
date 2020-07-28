package org.example;

import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;

import java.io.File;

import static java.util.Arrays.asList;
import static org.apache.kerby.kerberos.kerb.server.KdcConfigKey.PREAUTH_REQUIRED;

/**
 * Helper Class to start the KDC Server
 *
 */
public class KrbServerHelper
{
    public static void main( String[] args )
    {
        try {
            startKDCServer(null,null,10088);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void startKDCServer(String host, String realm, int port) throws Exception {
        SimpleKdcServer kdc = new SimpleKdcServer();


        if (host != null) {
            kdc.setKdcHost(host);
        }

        if (realm != null) {
            kdc.setKdcRealm(realm);
        }
        kdc.setKdcPort(port);
        kdc.setAllowUdp(false);
        kdc.getKdcConfig().setBoolean(PREAUTH_REQUIRED, false);
        kdc.init();

        kdc.createPrincipal("raj", "testpass");
        kdc.createPrincipal("saryu", "testpass1");
        kdc.createPrincipal("myservice/localhost", "testpass");

        File keytabFile = new File("service.keytab");
        if (!keytabFile.exists()) {
            kdc.getKadmin().exportKeytab(keytabFile, asList("myservice/localhost@EXAMPLE.COM"));
        }

        kdc.start();
        System.out.println("Starting Kerberos KDC Server on host: "+kdc.getKdcConfig().getKdcHost()
                +" port: "+kdc.getKdcConfig().getKdcPort());
    }
}
