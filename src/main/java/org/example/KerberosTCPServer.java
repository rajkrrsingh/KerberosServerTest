package org.example;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.MessageProp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.nio.charset.StandardCharsets.UTF_8;

public class KerberosTCPServer {

    public static void main(String[] args) throws IOException {

        System.setProperty("java.security.auth.login.config", "jaas.conf");
        System.setProperty("java.security.krb5.conf", "krb5.conf");
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "false");
        //System.setProperty("sun.security.krb5.debug", "true");
        //System.setProperty("sun.security.jgss.debug", "true");

        ExecutorService executorService = Executors.newFixedThreadPool(5);

        try (ServerSocket serverSocket = new ServerSocket(10003)) {
            System.out.println("Kerberos Server Started");
            while (true) {
                Socket acceptedSocket = serverSocket.accept();
                executorService.execute(new ClientConnectionHandler(acceptedSocket));
            }
        }
    }

    private static class ClientConnectionHandler implements Runnable {
        Socket acceptedSocket = null;
        public ClientConnectionHandler(Socket socket) {
            this.acceptedSocket = socket;
        }

        @Override
        public void run() {
            GSSContext gssContext = null;
            try (Socket socket = acceptedSocket) {
                gssContext = GSSManager.getInstance().createContext((GSSCredential) null);
                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
                // both parties will exchange token until the gssContext isExtablished.
                while (!gssContext.isEstablished()) {
                    byte[] inToken = new byte[dataInputStream.readInt()];
                    dataInputStream.readFully(inToken);
                    // acceptSecContext
                    byte[] outToken = gssContext.acceptSecContext(inToken, 0, inToken.length);

                    if (outToken != null) {
                        dataOutputStream.writeInt(outToken.length);
                        dataOutputStream.write(outToken);
                        dataOutputStream.flush();
                    }
                }
                String clientName = gssContext.getSrcName().toString();
                System.out.println("Context Established with Client " + clientName);

                byte[] wrappedMsg = new byte[dataInputStream.readInt()];
                dataInputStream.readFully(wrappedMsg);
                // qop can be set here
                MessageProp msgProp = new MessageProp(0, false);
                String msg = new String(gssContext.unwrap(wrappedMsg, 0, wrappedMsg.length, msgProp), UTF_8);
                System.out.println("Message Recieved from client: " + msg);

                String replyMsg = msg +  ", From Server";
                byte[] replyMsgBytes = replyMsg.getBytes(UTF_8);
                // preparing and sending back the replyMsg to client
                wrappedMsg = gssContext.wrap(replyMsgBytes, 0, replyMsgBytes.length, msgProp);

                dataOutputStream.writeInt(wrappedMsg.length);
                dataOutputStream.write(wrappedMsg);
                dataOutputStream.flush();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (gssContext != null) {
                    try {
                        gssContext.dispose();
                    } catch (GSSException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}
