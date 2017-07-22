package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.MMessageObject;
import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.MaladaN.Tor.thoughtcrime.ServerResponsePreKeyBundle;
import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.i2p.client.streaming.I2PSocket;
import net.strangled.maladan.serializables.*;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.SignalProtocolAddress;

import javax.xml.bind.DatatypeConverter;
import java.io.EOFException;
import java.io.ObjectInputStream;
import java.util.ArrayList;

public class ConnectionHandler implements Runnable {
    private Thread t;
    private I2PSocket sock;
    private User session = null;
    private ObjectInputStream in;
    private OutgoingMessageThread outThread;
    private boolean running = true;

    ConnectionHandler(I2PSocket sock) {
        this.sock = sock;
    }

    public void run() {

        try {
            in = new ObjectInputStream(sock.getInputStream());
            outThread = new OutgoingMessageThread(sock.getOutputStream());
            outThread.start();

            Thread t = new Thread(() -> {

                ArrayList<MMessageObject> messageForYouSir;

                while (running) {
                    try {
                        Thread.sleep(1000);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    if (session != null && !(messageForYouSir = GetServerSQLConnectionAndHandle.getPendingMessagesForClient(session.getUsername())).isEmpty()) {

                        for (MMessageObject o : messageForYouSir) {

                            try {
                                byte[] serializedMMessageObject = Server.serializeObject(o);
                                byte[] encryptedSerializedMessageObject = SignalCrypto.encryptByteMessage(serializedMMessageObject, new SignalProtocolAddress(session.getUsername(), 0), null);
                                EncryptedMMessageObject object = new EncryptedMMessageObject(encryptedSerializedMessageObject);

                                outThread.addNewMessage(object);
                                GetServerSQLConnectionAndHandle.removePendingMessages(session.getUsername());
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }

            });
            t.start();

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

                } else if (incoming instanceof EncryptedUser) {
                    EncryptedUser requestedUser = (EncryptedUser) incoming;
                    respondWithUserInformation(requestedUser);

                } else if (incoming instanceof EncryptedMMessageObject) {
                    EncryptedMMessageObject messageObject = (EncryptedMMessageObject) incoming;
                    handleAndQueueMessageObject(messageObject);

                }

            }

        } catch (EOFException e) {
            System.out.println("Socket Closed.");

        } catch (Exception e) {
            e.printStackTrace();

        } finally {

            try {
                if (sock != null) {
                    running = false;
                    in.close();
                    outThread.running = false;
                    sock.close();
                }

            } catch (Exception e) {
                System.out.println("Closed Resources.");
            }
        }
    }

    private void register(ServerInit init) throws Exception {
        System.out.println("Registering a user for the first Time.");

        if (init.getUniqueId().equals("tester123")) {

            //Store Client data.
            GetServerSQLConnectionAndHandle.storeConnectionInfo(init);

            //send the server preKeyBundle to the client.
            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo("SERVER".getBytes());

            if (data != null) {
                ServerResponsePreKeyBundle ps = data.getServerResponsePreKeyBundle();
                outThread.addNewMessage(ps);
                System.out.println("Added Username Successfully!");
            }

        } else {
            System.out.println("Invalid Registration");
        }
    }

    private void addPasswordToAccount(SignalEncryptedPasswordSend password) throws Exception {
        String username = password.getUsername();
        byte[] decryptedPasswordHash = SignalCrypto.decryptMessage(password.getSerializedPassword(), new SignalProtocolAddress(username, 0));
        byte[] decodedUsername = DatatypeConverter.parseBase64Binary(password.getUsername());
        RegistrationResponseState registrationResponseState = new RegistrationResponseState(GetServerSQLConnectionAndHandle.addPasswordToCompleteAccount(decodedUsername, decryptedPasswordHash));

        if (registrationResponseState.isValidRegistration()) {
            System.out.println("Added Account Password Successfully.");

            byte[] serializedRegistrationResponseState = Server.serializeObject(registrationResponseState);
            EncryptedRegistrationResponseState encryptedRegistrationResponseState = new EncryptedRegistrationResponseState(SignalCrypto.encryptByteMessage(serializedRegistrationResponseState, new SignalProtocolAddress(username, 0), null));

            this.session = new User(true, username);

            outThread.addNewMessage(encryptedRegistrationResponseState);
        }
    }

    private void loginAccount(ServerLogin login) throws Exception {
        String username = login.getEncodedHashedUsername();
        byte[] parsedUsername = DatatypeConverter.parseBase64Binary(username);

        if (GetServerSQLConnectionAndHandle.userExists(parsedUsername)) {

            byte[] decryptedPasswordHash = SignalCrypto.decryptMessage(login.getEncryptedPassword(), new SignalProtocolAddress(username, 0));

            boolean credentialsValid = GetServerSQLConnectionAndHandle.authenticateCredentials(parsedUsername, decryptedPasswordHash);
            boolean keyValid = false;

            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo(parsedUsername);
            if (data != null) {
                IdentityKey serverKey = data.getIdKey();
                IdentityKey userSentKey = new IdentityKey(login.getSerializedIdentityKey(), 0);

                if (serverKey.equals(userSentKey)) {
                    keyValid = true;
                }
            }

            boolean sessionValid = false;

            if (credentialsValid && keyValid) {
                sessionValid = true;
            }

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
            outThread.addNewMessage(state);
        }
    }

    private void respondWithUserInformation(EncryptedUser encryptedUser) throws Exception {

        if (session != null) {

            byte[] serializedUserObject = SignalCrypto.decryptMessage(encryptedUser.getEncryptedSerializedUser(), new SignalProtocolAddress(session.getUsername(), 0));
            User user = (User) Server.reconstructSerializedObject(serializedUserObject);

            byte[] actualUsername = DatatypeConverter.parseBase64Binary(user.getUsername());
            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo(actualUsername);

            if (data != null) {

                ServerResponsePreKeyBundle bundle = data.getServerResponsePreKeyBundle();

                byte[] serializedServerResponsePreKeyBundle = Server.serializeObject(bundle);
                byte[] encryptedSerializedServerResponeBundle = SignalCrypto.encryptByteMessage(serializedServerResponsePreKeyBundle, new SignalProtocolAddress(session.getUsername(), 0), null);

                EncryptedClientPreKeyBundle encryptedClientPreKeyBundle = new EncryptedClientPreKeyBundle(encryptedSerializedServerResponeBundle);

                outThread.addNewMessage(encryptedClientPreKeyBundle);

            } else {
                UserExistsState state = new UserExistsState(false);
                outThread.addNewMessage(state);
            }
        }
    }

    private void handleAndQueueMessageObject(EncryptedMMessageObject encryptedObject) throws Exception {
        byte[] serializedMMessageObject = SignalCrypto.decryptMessage(encryptedObject.getEncryptedSerializedMMessageObject(), new SignalProtocolAddress(session.getUsername(), 0));
        MMessageObject object = (MMessageObject) Server.reconstructSerializedObject(serializedMMessageObject);

        GetServerSQLConnectionAndHandle.storePendingMessage(object.getDestinationUser(), object);
    }

    private void encryptAndSendLoginState(LoginResponseState state) throws Exception {
        byte[] encryptedState = SignalCrypto.encryptByteMessage(Server.serializeObject(state), new SignalProtocolAddress(this.session.getUsername(), 0), null);
        EncryptedLoginResponseState loginState = new EncryptedLoginResponseState(encryptedState);

        outThread.addNewMessage(loginState);
    }

    void start() {
        System.out.println("Starting: new ConnectionHandler");
        if (t == null) {
            t = new Thread(this);
            t.start();
        }
    }
}
