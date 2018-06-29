package net.strangled.maladan;


import net.MaladaN.Tor.thoughtcrime.GetSQLConnection;
import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.strangled.maladan.serializables.Authentication.ServerInit;
import net.strangled.maladan.serializables.Messaging.MMessageObject;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;


class GetServerSQLConnectionAndHandle {

    static void storeConnectionInfo(ServerInit init) {

        if (!userExists(init.getUsername())) {

            try {
                Connection conn = GetSQLConnection.getConn();

                if (conn != null) {
                    String sql = "INSERT INTO serverSignalCryptoData (username, pullableInitData, uniqueId) VALUES (?, ?, ?)";
                    PreparedStatement ps = conn.prepareStatement(sql);
                    ps.setString(1, init.getUsername());


                    ps.setBytes(2, Server.serializeObject(init.getInitData()));
                    ps.setString(3, init.getUniqueId());
                    ps.execute();
                    conn.close();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    static synchronized void updateConnectionInfo(SendInitData updatedData, String username) {
        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "UPDATE serverSignalCryptoData SET pullableInitData = ? WHERE username = ?";

                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, Server.serializeObject(updatedData));
                ps.setString(2, username);
                ps.execute();

                conn.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static boolean addPasswordToCompleteAccount(String username, String password) {

        if (userExists(username)) {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {

                try {
                    String sql = "UPDATE serverSignalCryptoData SET hashedPassword = ? WHERE username = ?";
                    PreparedStatement ps = conn.prepareStatement(sql);

                    String hash = Server.hashDataWithSalt(password);

                    ps.setString(1, hash);
                    ps.setString(2, username);
                    ps.execute();
                    conn.close();
                    return true;

                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }

            } else {
                return false;
            }

        } else {
            return false;
        }
    }

    static SendInitData getConnectionInfo(String username) {
        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "SELECT pullableInitData FROM serverSignalCryptoData WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();

                if (rs.next()) {
                    byte[] serializedServerInitObject = rs.getBytes("pullableInitData");

                    ByteArrayInputStream bis = new ByteArrayInputStream(serializedServerInitObject);
                    ObjectInput in = null;

                    try {
                        in = new ObjectInputStream(bis);
                        return (SendInitData) in.readObject();
                    } finally {
                        try {
                            if (in != null) {
                                in.close();
                            }
                        } catch (IOException ex) {
                            // ignore close exception
                        }
                    }
                }
                conn.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static void removeConnectionInfo(String username) {
        //Executed by a user to scrub their preKeys from the server.

        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "DELETE FROM serverSignalCryptoData WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);
                ps.execute();
                conn.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static boolean userExists(String username) {

        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "SELECT * FROM serverSignalCryptoData WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                boolean returnable = rs.next();
                conn.close();
                return returnable;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    static boolean authenticateCredentials(String username, String password) {
        Connection conn = GetSQLConnection.getConn();

        try {

            if (conn != null) {
                String sql = "SELECT hashedPassword FROM serverSignalCryptoData WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);

                ResultSet rs = ps.executeQuery();
                boolean valid = false;

                while (rs.next()) {
                    String passwordHash = rs.getString("hashedPassword");
                    valid = Server.verifyHash(passwordHash, password);
                }
                conn.close();
                return valid;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }


    static ArrayList<MMessageObject> getPendingMessagesForClient(String username) {
        Connection conn = GetSQLConnection.getConn();

        try {

            if (conn != null) {
                String sql = "SELECT * FROM escrowMessages where username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();

                ArrayList<MMessageObject> objects = new ArrayList<>();

                while (rs.next()) {
                    byte[] serialializedMmOBject = rs.getBytes("mMessage");
                    MMessageObject messageObject = (MMessageObject) Server.reconstructSerializedObject(serialializedMmOBject);
                    objects.add(messageObject);
                }
                conn.close();
                return objects;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }

    static void storePendingMessage(String clientUsername, MMessageObject messageObject) {
        Connection conn = GetSQLConnection.getConn();

        try {

            if (conn != null) {
                byte[] serializedMessageObject = Server.serializeObject(messageObject);

                String sql = "INSERT INTO escrowMessages (username, mMessage) VALUES (?, ?)";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, clientUsername);
                ps.setBytes(2, serializedMessageObject);
                ps.execute();
                conn.close();

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static void removePendingMessages(String clientUsername) {
        Connection conn = GetSQLConnection.getConn();

        try {

            if (conn != null) {
                String sql = "DELETE FROM escrowMessages WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, clientUsername);
                ps.execute();
                conn.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
