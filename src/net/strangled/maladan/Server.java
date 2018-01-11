package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.InitData;
import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.data.PrivateKeyFile;
import net.strangled.maladan.serializables.Authentication.ServerInit;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Server {

    public static void main(String[] args) {
        //Initialize application

        InputStream file = null;

        try {
            PrivateKeyFile data = new PrivateKeyFile(new File("./destination.mal"));
            data.createIfAbsent();
            file = new FileInputStream("./destination.mal");

        } catch (Exception e) {
            e.printStackTrace();
        }
        //This is where to change the address and port to reflect your i2cp host.
        I2PSocketManager manager = I2PSocketManagerFactory.createManager(file, "1.1.1.33", 7654, null);
        I2PServerSocket serverSocket = manager.getServerSocket();
        I2PSession session = manager.getSession();

        //Print the base64 string, the regular string would look like garbage.
        System.out.println(session.getMyDestination().toBase64());

        try {
            InitData data = SignalCrypto.initStore();

            if (data != null) {
                ServerInit init = new ServerInit("SERVER".getBytes(), "SERVER", data);
                GetServerSQLConnectionAndHandle.storeConnectionInfo(init);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {

            while (true) {
                I2PSocket sock = serverSocket.accept();
                new ConnectionHandler(sock).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    static byte[] serializeObject(Object object) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(object);
        out.flush();
        return bos.toByteArray();
    }

    static Object reconstructSerializedObject(byte[] object) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(object);
        ObjectInput in = new ObjectInputStream(bis);
        return in.readObject();
    }

    static byte[] hashData(String data) throws NoSuchAlgorithmException {
        return hashData(data.getBytes());
    }

    static byte[] hashData(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(data);
        return messageDigest.digest();
    }

}
