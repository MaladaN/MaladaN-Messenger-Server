package net.MaladaN.Tor.thoughtcrime;


import org.whispersystems.libsignal.IdentityKeyPair;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class InitStore {
    static void storeIdentityKeyPairAndRegistrationId(IdentityKeyPair identityKeyPair, int localRegistrationId) {
        Connection conn = GetSQLConnection.getConn();
        if (conn != null) {
            String sql = "INSERT INTO localIdentityStorage (identityKeyPair, localRegistrationId) VALUES (?, ?)";
            try {
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, identityKeyPair.serialize());
                ps.setInt(2, localRegistrationId);
                ps.execute();
                conn.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public static IdentityKeyPair getIdentityKeyPair() {
        Connection conn = GetSQLConnection.getConn();

        if (conn != null) {
            String sql = "SELECT identityKeyPair FROM localIdentityStorage";
            try {
                PreparedStatement ps = conn.prepareStatement(sql);
                ResultSet rs = ps.executeQuery();

                if (rs.next()) {
                    byte[] serializedKeyPair = rs.getBytes("identityKeyPair");
                    conn.close();
                    return new IdentityKeyPair(serializedKeyPair);

                } else {
                    conn.close();
                    return null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    static void setInstalledFlagTrue() {
        Connection conn = GetSQLConnection.getConn();
        if (conn != null) {
            String sql = "INSERT INTO installedFlag (flag) VALUES (1)";
            try {
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.execute();
                conn.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static boolean isInstalled() {
        Connection conn = GetSQLConnection.getConn();
        if (conn != null) {
            String sql = "SELECT flag FROM installedFlag";
            try {
                PreparedStatement ps = conn.prepareStatement(sql);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    int flag = rs.getInt("flag");
                    conn.close();
                    return (flag == 1);
                } else {
                    conn.close();
                    return false;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return false;
    }
}
