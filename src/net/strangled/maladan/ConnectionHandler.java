package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.MaladaN.Tor.thoughtcrime.ServerResponsePreKeyBundle;
import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.i2p.client.streaming.I2PSocket;
import net.strangled.maladan.serializables.Authentication.*;
import net.strangled.maladan.serializables.Messaging.*;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.SignalProtocolAddress;

import java.io.EOFException;
import java.io.ObjectInputStream;

public class ConnectionHandler implements Runnable {
    private Thread t;
    private I2PSocket sock;
    private User session = null;
    private ObjectInputStream in;
    private OutgoingMessageThread outThread;
    private boolean running = true;

    User getSession() {
        if (session != null) {
            return new User(session.isLoggedIn(), session.getUsername());
        }
        return null;
    }

    OutgoingMessageThread getOutThread() {
        return outThread;
    }

    boolean isRunning() {
        return running;
    }

    ConnectionHandler(I2PSocket sock) {
        this.sock = sock;
    }

    public void run() {

        try {
            in = new ObjectInputStream(sock.getInputStream());
            outThread = new OutgoingMessageThread(sock.getOutputStream());
            outThread.start();

            //start message handling thread for the user that this thread handles
            SendMessageToClientThread messageThread = new SendMessageToClientThread(this);
            messageThread.start();

            while (running) {
                Object incoming = in.readObject();

                if (incoming instanceof IEncryptedAuth) {
                    if (incoming instanceof EncryptedUser) {
                        EncryptedUser requestedUser = (EncryptedUser) incoming;
                        respondWithUserInformation(requestedUser);
                    }

                } else if (incoming instanceof IEncryptedMessage) {
                    if (incoming instanceof EncryptedMMessageObject) {
                        EncryptedMMessageObject messageObject = (EncryptedMMessageObject) incoming;
                        handleAndQueueMessageObject(messageObject);

                    } else if (incoming instanceof EncryptedFileInitiation) {
                        System.out.println("Received the start of a file");

                    } else if (incoming instanceof EncryptedFileSpan) {
                        System.out.println("Received a span piece of file");

                    } else if (incoming instanceof EncryptedFileEnd) {
                        System.out.println("Received End of File");
                    }

                } else {

                    if (incoming instanceof ServerInit) {
                        ServerInit init = (ServerInit) incoming;
                        register(init);

                    } else if (incoming instanceof ServerLogin) {
                        ServerLogin login = (ServerLogin) incoming;
                        loginAccount(login);

                    } else if (incoming instanceof SignalEncryptedPasswordSend) {
                        //receive the user password encrypted with the newly created session between the client and server.
                        SignalEncryptedPasswordSend passwordSend = (SignalEncryptedPasswordSend) incoming;
                        addPasswordToAccount(passwordSend);

                    }
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

    /*
     *  This method takes the ServerInit object sent in from the user, checks to make sure that the user has a valid
     *  unique id, then stores the connection information of the new client.
     *
     *  A pre key bundle is then sent back to the client, so that all future communications can be done within a signal
     *  session.
     *
     *  After receiving the bundle, the client will respond with their password encrypted using the new session.
     */

    private void register(ServerInit init) throws Exception {
        System.out.println("Registering a user for the first Time.");

        if (init.getUniqueId().equals("tester123")) {

            //Store Client data.
            GetServerSQLConnectionAndHandle.storeConnectionInfo(init);

            //send the server preKeyBundle to the client.
            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo("SERVER");

            if (data != null) {
                ServerResponsePreKeyBundle ps = data.getServerResponsePreKeyBundle();

                //check if we are out of pre keys. If we are, generate more.
                if (ps == null) {
                    data = Server.addMorePreKeys(data);

                    if (data != null) {
                        ps = data.getServerResponsePreKeyBundle();

                    } else {
                        throw new Exception("Error. The system was unable to add more pre-keys to the server account.");
                    }
                }

                outThread.addNewMessage(ps);
                System.out.println("Added Username Successfully!");

                //update data saved in the database with the now removed pre key
                GetServerSQLConnectionAndHandle.updateConnectionInfo(data, "SERVER");
            }

        } else {
            System.out.println("Invalid Registration");
        }
    }

    /*
     *  After a new user has registered their new username for the first time, they will respond with their password,
     *  encrypted using the new session that was established in the register method. This method takes the encrypted
     *  password message as a parameter, and then decrypts it, hashes it, and adds it to the user's record in the
     *  database.
     */

    private void addPasswordToAccount(SignalEncryptedPasswordSend password) throws Exception {
        String username = password.getUsername();

        String decryptedPassword = SignalCrypto.decryptStringMessage(password.getSerializedPassword(), new SignalProtocolAddress(username, 0));
        RegistrationResponseState registrationResponseState = new RegistrationResponseState(GetServerSQLConnectionAndHandle.addPasswordToCompleteAccount(username, decryptedPassword));

        if (registrationResponseState.isValidRegistration()) {
            System.out.println("Added Account Password Successfully.");

            byte[] serializedRegistrationResponseState = Server.serializeObject(registrationResponseState);
            byte[] encryptedResponse = SignalCrypto.encryptByteMessage(serializedRegistrationResponseState,
                    new SignalProtocolAddress(username, 0), null);

            IEncryptedAuth encryptedRegistrationResponseState = new EncryptedRegistrationResponseState();
            encryptedRegistrationResponseState.storeEncryptedData(encryptedResponse);

            this.session = new User(true, username);

            outThread.addNewMessage(encryptedRegistrationResponseState);
        }
    }

    /*
     *  This method handles the authentication of existing users in the database. If the user's credentials are valid,
     *  they will be granted a valid session with the server, and be able to send messages to other users. Otherwise they
     *  will be sent a response notifying them that their credentials are invalid.
     */

    private void loginAccount(ServerLogin login) throws Exception {
        String username = login.getUsername();

        if (GetServerSQLConnectionAndHandle.userExists(username)) {

            String decryptedPassword = SignalCrypto.decryptStringMessage(login.getEncryptedPassword(), new SignalProtocolAddress(username, 0));

            boolean credentialsValid = GetServerSQLConnectionAndHandle.authenticateCredentials(username, decryptedPassword);
            boolean keyValid = false;

            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo(username);
            if (data != null) {
                //make sure that the key the user sends with their login matches the key that the server has
                //on record
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

    /*
     *  This method is called when a user wants to send a message to another user for the first time. The requesting user
     *  sends the server the destination user's username, and the server responds with public key information for the
     *  destination user, so that the requesting user can build a new signal session with the destination user.
     */

    private void respondWithUserInformation(EncryptedUser encryptedUser) throws Exception {

        if (session != null) {

            byte[] serializedUserObject = SignalCrypto.decryptMessage(encryptedUser.getEncryptedData(),
                    new SignalProtocolAddress(session.getUsername(), 0));

            User user = (User) Server.reconstructSerializedObject(serializedUserObject);

            String requestedUserUsername = user.getUsername();

            SendInitData data = GetServerSQLConnectionAndHandle.getConnectionInfo(requestedUserUsername);

            if (data != null) {

                ServerResponsePreKeyBundle bundle = data.getServerResponsePreKeyBundle();

                //update user the record was pulled from, as it now has one less pre key
                GetServerSQLConnectionAndHandle.updateConnectionInfo(data, requestedUserUsername);

                byte[] serializedServerResponsePreKeyBundle = Server.serializeObject(bundle);
                byte[] encryptedSerializedServerResponseBundle = SignalCrypto.encryptByteMessage(serializedServerResponsePreKeyBundle,
                        new SignalProtocolAddress(session.getUsername(), 0), null);

                IEncryptedAuth encryptedClientPreKeyBundle = new EncryptedClientPreKeyBundle();
                encryptedClientPreKeyBundle.storeEncryptedData(encryptedSerializedServerResponseBundle);

                outThread.addNewMessage(encryptedClientPreKeyBundle);

            } else {
                UserExistsState state = new UserExistsState(false);
                outThread.addNewMessage(state);
            }
        }
    }

    /*
     *  This method handles messages received by the server that are destined for clients. It queues them in the
     *  database until the destination user is available to receive the message.
     */

    private void handleAndQueueMessageObject(EncryptedMMessageObject encryptedObject) throws Exception {
        byte[] serializedMMessageObject = SignalCrypto.decryptMessage(encryptedObject.getEncryptedMessage(), new SignalProtocolAddress(session.getUsername(), 0));
        MMessageObject object = (MMessageObject) Server.reconstructSerializedObject(serializedMMessageObject);

        GetServerSQLConnectionAndHandle.storePendingMessage(object.getDestinationUser(), object);
    }

    /*
     *  This method is used to encrypt authentication responses to users, telling client applications whether they now
     *  have a valid session or not.
     */

    private void encryptAndSendLoginState(LoginResponseState state) throws Exception {
        byte[] encryptedState = SignalCrypto.encryptByteMessage(Server.serializeObject(state),
                new SignalProtocolAddress(this.session.getUsername(), 0), null);

        IEncryptedAuth loginState = new EncryptedLoginResponseState();
        loginState.storeEncryptedData(encryptedState);

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
