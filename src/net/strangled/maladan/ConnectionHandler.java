package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.MaladaN.Tor.thoughtcrime.ServerResponsePreKeyBundle;
import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.i2p.client.streaming.I2PSocket;
import org.whispersystems.libsignal.SignalProtocolAddress;

import javax.xml.bind.DatatypeConverter;
import java.io.*;

public class ConnectionHandler implements Runnable {
    private Thread t;
    private I2PSocket sock;
    private User session = null;
    private ObjectOutputStream out;
    private ObjectInputStream in;

    ConnectionHandler(I2PSocket sock) {
        this.sock = sock;
    }

    public void run() {

        try {
            in = new ObjectInputStream(sock.getInputStream());
            out = new ObjectOutputStream(sock.getOutputStream());

            while (true) {
                Object incoming = in.readObject();

                if (incoming instanceof ServerInit) {
                    ServerInit init = (ServerInit) incoming;
                    register(init);

                } else if (incoming instanceof SignalEncryptedPasswordSend) {
                    //receive the user password encrypted with the newly created session between the client and server.
                    SignalEncryptedPasswordSend passwordSend = (SignalEncryptedPasswordSend) incoming;
                    addPasswordToAccount(passwordSend);

                    //Account Valid. Proceed To Login (With encrypted Session)
                } else if (incoming instanceof ServerLogin) {
                    ServerLogin login = (ServerLogin) incoming;
                    loginAccount(login);
                }

            }

        } catch (EOFException e) {
            System.out.println("Socket Closed.");

        } catch (Exception e) {
            e.printStackTrace();

        } finally {

            try {
                if (sock != null) {
                    in.close();
                    out.close();
                    sock.close();
                }

            } catch (Exception e) {
                System.out.println("Closed Resources.");
            }
        }
    }

    private void register(ServerInit init) throws IOException {
        System.out.println("Registering a user for the first Time.");

        if (init.getUniqueId().equals("tester123")) {

            //Store Client data.
            GetServerSQLConnectionAndHandle.storeConnectionInfo(init);

            //send the server preKeyBundle to the client.
            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo("SERVER".getBytes());

            if (data != null) {
                ServerResponsePreKeyBundle ps = data.getServerResponsePreKeyBundle();
                out.writeObject(ps);
                out.flush();
                System.out.println("Added Username Successfully!");
            }

        } else {
            System.out.println("Invalid Registration");
        }
    }

    private void addPasswordToAccount(SignalEncryptedPasswordSend password) throws Exception {
        byte[] decryptedPasswordHash = SignalCrypto.decryptMessage(password.getSerializedPassword(), new SignalProtocolAddress(password.getUsername(), 0));
        GetServerSQLConnectionAndHandle.addPasswordToCompleteAccount(DatatypeConverter.parseBase64Binary(password.getUsername()), decryptedPasswordHash);
        System.out.println("Added Account Password Successfully.");

        RegistrationResponseState registrationResponseState = new RegistrationResponseState(true);
        byte[] serializedRegistrationResponseState = serializeObject(registrationResponseState);
        EncryptedRegistrationState encryptedRegistrationState = new EncryptedRegistrationState(SignalCrypto.encryptByteMessage(serializedRegistrationResponseState, new SignalProtocolAddress(password.getUsername(), 0), null));

        out.writeObject(encryptedRegistrationState);
        out.flush();
    }

    private void loginAccount(ServerLogin login) throws Exception {
        String username = login.getEncodedHashedUsername();
        byte[] parsedUsername = DatatypeConverter.parseBase64Binary(username);

        if (GetServerSQLConnectionAndHandle.userExists(parsedUsername)) {

            byte[] decryptedPasswordHash = SignalCrypto.decryptMessage(login.getEncryptedPassword(), new SignalProtocolAddress(username, 0));
            boolean sessionValid = GetServerSQLConnectionAndHandle.authenticateCredentials(parsedUsername, decryptedPasswordHash);
            this.session = new User(sessionValid, username);

            if (sessionValid) {
                LoginResponseState state = new LoginResponseState(true);
                encryptAndSendLoginState(state);

            } else {
                LoginResponseState state = new LoginResponseState(false);
                encryptAndSendLoginState(state);
            }
        } else {
            LoginResponseState state = new LoginResponseState(false);
            out.writeObject(state);
            out.flush();
        }
    }

    private void encryptAndSendLoginState(LoginResponseState state) throws Exception {
        byte[] encryptedState = SignalCrypto.encryptByteMessage(serializeObject(state), new SignalProtocolAddress(this.session.getBase64Username(), 0), null);
        EncryptedLoginState loginState = new EncryptedLoginState(encryptedState);

        out.writeObject(loginState);
        out.flush();
    }

    private byte[] serializeObject(Object object) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(object);
        out.flush();
        return bos.toByteArray();
    }

    private Object reconstructSerializedObject(byte[] object) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(object);
        ObjectInput in = new ObjectInputStream(bis);
        return in.readObject();
    }

    void start() {
        System.out.println("Starting: new ConnectionHandler");
        if (t == null) {
            t = new Thread(this);
            t.start();
        }
    }
}
