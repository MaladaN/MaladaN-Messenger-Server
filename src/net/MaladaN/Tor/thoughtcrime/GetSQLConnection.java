package net.MaladaN.Tor.thoughtcrime;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

public class GetSQLConnection {
    private static int initialFlag = 0;

    public static void setInitialFlag() {
        initialFlag = 1;
    }

    public static int getInitialFlag() {
        return initialFlag;
    }

    public static Connection getConn() {
        try {
            if (getInitialFlag() == 1) {
                Class.forName("org.h2.Driver");
                return DriverManager.
                        getConnection("jdbc:h2:./DB/M_DB", "Shinobu", "Oshino");
            } else {
                setInitialFlag();
                return initDBReturnConnection();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static Connection initDBReturnConnection() {
        try {
            Class.forName("org.h2.Driver");
            Connection conn = DriverManager.
                    getConnection("jdbc:h2:./DB/M_DB", "Shinobu", "Oshino");


            //Signal Data Tables

            String identityKeyStoreTable = "CREATE TABLE IF NOT EXISTS identityKeyStorage (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    " identityKeypair longblob, localRegistrationId int(10), signalProtocolAddress VARCHAR(64), identityKey longblob, PRIMARY KEY (id))";
            PreparedStatement ps = conn.prepareStatement(identityKeyStoreTable);
            ps.execute();

            String localRegIdAndIdentity = "CREATE TABLE IF NOT EXISTS localIdentityStorage (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    " identityKeyPair longblob, localRegistrationId int(10), PRIMARY KEY (id))";
            ps = conn.prepareStatement(localRegIdAndIdentity);
            ps.execute();

            String preKeyStoreTable = "CREATE TABLE IF NOT EXISTS preKeyStorage (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    " preKeyRecord longblob, keyId int(10), PRIMARY KEY (id))";
            ps = conn.prepareStatement(preKeyStoreTable);
            ps.execute();

            String sessionStoreTable = "CREATE TABLE IF NOT EXISTS sessionStoreStorage (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    " protocolAddress VARCHAR(64), sessionRecord longblob, PRIMARY KEY (id))";
            ps = conn.prepareStatement(sessionStoreTable);
            ps.execute();

            String signedPreKeyTable = "CREATE TABLE IF NOT EXISTS signedPreKeyStore (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    " signedPreKeyRecord longblob, keyId int(10),  PRIMARY KEY (id))";
            ps = conn.prepareStatement(signedPreKeyTable);
            ps.execute();

            String installedFlag = "CREATE TABLE IF NOT EXISTS installedFlag (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    "flag int(10), PRIMARY KEY (id))";
            ps = conn.prepareStatement(installedFlag);
            ps.execute();

            //Server Data Table

            String sql = "CREATE TABLE IF NOT EXISTS serverSignalCryptoData (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    "username VARCHAR(128), hashedPassword VARCHAR(256), pullableInitData longblob, uniqueId varchar(128),PRIMARY KEY (id))";
            ps = conn.prepareStatement(sql);
            ps.execute();

            String escrowMessages = "CREATE TABLE IF NOT EXISTS escrowMessages (id int(10) unsigned NOT NULL AUTO_INCREMENT," +
                    "username VARCHAR(128), mMessage longblob, PRIMARY KEY(id))";
            ps = conn.prepareStatement(escrowMessages);
            ps.execute();

            return conn;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
