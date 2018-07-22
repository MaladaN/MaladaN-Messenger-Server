package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.strangled.maladan.serializables.Authentication.User;
import net.strangled.maladan.serializables.Messaging.EncryptedMMessageObject;
import net.strangled.maladan.serializables.Messaging.IEncryptedMessage;
import net.strangled.maladan.serializables.Messaging.MMessageObject;
import org.whispersystems.libsignal.SignalProtocolAddress;

import java.util.ArrayList;

public class SendMessageToClientThread implements Runnable {
    private Thread t = null;
    private ConnectionHandler handler;

    SendMessageToClientThread(ConnectionHandler handler) {
        this.handler = handler;
    }

    /*
     * This method checks the database once per second to see if the particular user this thread is running for
     * has and incoming String message objects that can be sent to them.
     */
    @Override
    public void run() {
        User session = null;
        OutgoingMessageThread outThread = handler.getOutThread();
        ArrayList<MMessageObject> messageForYouSir;

        while (handler.isRunning()) {

            try {
                Thread.sleep(1000);
            } catch (Exception e) {
                e.printStackTrace();
            }

            session = (session == null) ? handler.getSession() : session;

            if (session != null && !(messageForYouSir = GetServerSQLConnectionAndHandle.getPendingMessagesForClient(session.getUsername())).isEmpty()) {
                GetServerSQLConnectionAndHandle.removePendingMessages(session.getUsername());

                for (MMessageObject o : messageForYouSir) {

                    try {
                        byte[] serializedMMessageObject = Server.serializeObject(o);
                        byte[] encryptedSerializedMessageObject = SignalCrypto.encryptByteMessage(serializedMMessageObject, new SignalProtocolAddress(session.getUsername(), 0), null);
                        IEncryptedMessage object = new EncryptedMMessageObject();
                        object.storeEncryptedMessage(encryptedSerializedMessageObject);

                        outThread.addNewMessage(object);

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    public void start() {
        if (t == null) {
            t = new Thread(this);
            t.start();
        }
    }
}
