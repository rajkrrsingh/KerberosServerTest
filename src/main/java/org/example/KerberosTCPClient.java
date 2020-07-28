package org.example;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import org.ietf.jgss.Oid;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.concurrent.Callable;

import static java.nio.charset.StandardCharsets.UTF_8;


public class KerberosTCPClient {

    public static void main(String[] args) throws Exception {
        try {
            //System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.auth.login.config", "jaas.conf");
            System.setProperty("java.security.krb5.conf", "krb5.conf");
            System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");

            try (Socket socket = new Socket("localhost", 10003)) {
                DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                DataInputStream dis = new DataInputStream(socket.getInputStream());
                String token = KerberosUtils.doAs("raj@EXAMPLE.COM", "testpass".toCharArray(), new Callable<String>() {
                    @Override
                    public String call() throws Exception {


                        GSSManager gssManager = GSSManager.getInstance();
                        GSSContext gssContext = null;
                        try {
                            String servicePrincipal = "myservice/localhost@EXAMPLE.COM";
                            GSSName serviceName = gssManager.createName(servicePrincipal,
                                    null);
                            gssContext = gssManager.createContext(serviceName, new Oid("1.2.840.113554.1.2.2"),
                                    null,
                                    GSSContext.DEFAULT_LIFETIME);
                            gssContext.requestMutualAuth(true);
                            gssContext.requestConf(false);
                            gssContext.requestInteg(false);

                            byte[] token = new byte[0];
                            while (!gssContext.isEstablished()) {
                                token = gssContext.initSecContext(token, 0, token.length);
                                if (token != null) {
                                    dos.writeInt(token.length);
                                    dos.write(token);
                                    dos.flush();
                                }
                                if (!gssContext.isEstablished()) {
                                    token = new byte[dis.readInt()];
                                    dis.readFully(token);
                                }
                            }
                            String requestMsg = "Client:Hello";
                            byte[] requestMsgBytes = requestMsg.getBytes(UTF_8);
                            MessageProp msgProp = new MessageProp(true);
                            token = gssContext.wrap(requestMsgBytes, 0, requestMsgBytes.length, msgProp);
                            System.out.println("Message privacy used for sending: " + msgProp.getPrivacy());

                            dos.writeInt(token.length);
                            dos.write(token);
                            dos.flush();

                            token = new byte[dis.readInt()];
                            dis.readFully(token);
                            msgProp = new MessageProp(false);
                            byte[] replyMsgBytes = gssContext.unwrap(token, 0, token.length, msgProp);
                            System.out.println("Message privacy used for received reply: " + msgProp.getPrivacy());

                            return new String(replyMsgBytes, UTF_8);

                        } finally {
                            if (gssContext != null) {
                                gssContext.dispose();
                            }
                            //KerberosUtils.stopKDCServer();

                        }
                    }
                });

                System.out.println("Client recieved Resp from Server :: "+token);

            }

        } finally {
        }
    }
}


