package org.example;



import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.Callable;


public class KerberosUtils {


    public static <T> T doAs(String principal, char[] passArr, final Callable<T> callable) throws Exception {
        LoginContext loginContext = null;
        try {
            loginContext = new LoginContext("KerbLogin",
                    new CallbackHandler() {

                        @Override
                        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                            for (Callback cb : callbacks) {
                                if (cb instanceof NameCallback) {
                                    NameCallback nc = (NameCallback) cb;
                                    nc.setName(principal);
                                } else if (cb instanceof PasswordCallback) {
                                    PasswordCallback pc = (PasswordCallback) cb;
                                    pc.setPassword(passArr);
                                } else {
                                    throw new UnsupportedCallbackException(cb);
                                }
                            }
                        }
                    });
            loginContext.login();
            Subject subject = loginContext.getSubject();
            KerberosTicket kt = (KerberosTicket) subject.getPrivateCredentials().iterator().next();
            System.out.println("client auth succeed, kerbero ticket "+kt);
            return Subject.doAs(subject, new PrivilegedExceptionAction<T>() {
                @Override
                public T run() throws Exception {
                    return callable.call();
                }
            });
        } catch (PrivilegedActionException ex) {
            throw ex.getException();
        } finally {
            if (loginContext != null) {
                loginContext.logout();
            }
        }
    }

}

