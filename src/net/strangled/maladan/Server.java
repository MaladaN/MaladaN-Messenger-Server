package net.strangled.maladan;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import net.MaladaN.Tor.thoughtcrime.InitData;
import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.MaladaN.Tor.thoughtcrime.SignalCrypto;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.data.PrivateKeyFile;
import net.strangled.maladan.serializables.Authentication.ServerInit;
import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.Trigger;
import org.quartz.impl.StdSchedulerFactory;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

import java.io.*;
import java.util.List;

import static org.quartz.JobBuilder.newJob;
import static org.quartz.SimpleScheduleBuilder.simpleSchedule;
import static org.quartz.TriggerBuilder.newTrigger;

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
        I2PSocketManager manager = I2PSocketManagerFactory.createManager(file, "10.0.0.32", 7654, null);
        I2PServerSocket serverSocket = manager.getServerSocket();
        I2PSession session = manager.getSession();

        //Print the base64 string, the regular string would look like garbage.
        System.out.println(session.getMyDestination().toBase64());

        //create signal server user profile
        try {
            InitData data = SignalCrypto.initStore();

            if (data != null) {
                ServerInit init = new ServerInit("SERVER", "SERVER", data);
                GetServerSQLConnectionAndHandle.storeConnectionInfo(init);
            }

            //schedule server's signedPreKey to change once a week.
            Scheduler jobScheduler = StdSchedulerFactory.getDefaultScheduler();

            JobDetail signedPreKeyUpdateJob = newJob(signedPreKeyJob.class)
                    .withIdentity("Pre Key Change", "Weekly")
                    .build();

            Trigger signedPreKeyUpdateTrigger = newTrigger()
                    .withIdentity("Time Interval", "Weekly")
                    .startNow()
                    .withSchedule(simpleSchedule()
                            .withIntervalInHours(168)
                            .repeatForever())
                    .build();

            jobScheduler.scheduleJob(signedPreKeyUpdateJob, signedPreKeyUpdateTrigger);

            jobScheduler.start();

        } catch (Exception e) {
            e.printStackTrace();
        }

        //accept connections from users
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
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ObjectOutput out = new ObjectOutputStream(bos);
            out.writeObject(object);
            out.flush();
            return bos.toByteArray();
        }
    }

    static Object reconstructSerializedObject(byte[] object) throws Exception {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(object)) {
            ObjectInput in = new ObjectInputStream(bis);
            return in.readObject();
        }
    }

    static synchronized SendInitData addMorePreKeys(SendInitData data) {
        SendInitData checkData = GetServerSQLConnectionAndHandle.getConnectionInfo("SERVER");
        int numberOfKeys = 0;

        if (checkData != null && (numberOfKeys = checkData.getNumberOfPreKeys()) == 0) {
            List<PreKeyRecord> records = KeyHelper.generatePreKeys(2, 1000);
            data.addPreKeys(records);
            return data;

        } else if (numberOfKeys > 0) {
            return checkData;
        }
        return null;
    }

    static String hashDataWithSalt(String data) {
        Argon2 argon2 = Argon2Factory.create();
        return argon2.hash(2, 65536, 4, data);
    }

    static boolean verifyHash(String hash, String pass) {
        Argon2 argon2 = Argon2Factory.create();
        return argon2.verify(hash, pass);
    }

}
