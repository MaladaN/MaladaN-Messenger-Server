package net.strangled.maladan;


import net.MaladaN.Tor.thoughtcrime.GetSQLConnection;
import net.MaladaN.Tor.thoughtcrime.MMessageObject;
import net.MaladaN.Tor.thoughtcrime.SendInitData;
import net.strangled.maladan.serializables.ServerInit;

import java.io.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;


class GetServerSQLConnectionAndHandle {

    static void storeConnectionInfo(ServerInit init) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        if (!userExists(init.getUsername())) {

            try {
                Connection conn = GetSQLConnection.getConn();

                if (conn != null) {
                    String sql = "INSERT INTO serverSignalCryptoData (hashedUsername, pullableInitData, uniqueId) VALUES (?, ?, ?)";
                    PreparedStatement ps = conn.prepareStatement(sql);
                    ps.setBytes(1, Server.hashData(init.getUsername()));

                    ObjectOutput out;
                    out = new ObjectOutputStream(bos);
                    out.writeObject(init.getInitData());
                    out.flush();
                    ps.setBytes(2, bos.toByteArray());
                    ps.setString(3, init.getUniqueId());
                    ps.execute();
                    conn.close();
                }

            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    bos.close();
                } catch (IOException ex) {
                    // ignore close exception
                }
            }
        }
    }

    static boolean addPasswordToCompleteAccount(byte[] username, byte[] password) {

        if (userExists(username)) {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {

                try {
                    String sql = "UPDATE serverSignalCryptoData SET hashedPassword = ? WHERE hashedUsername = ?";
                    PreparedStatement ps = conn.prepareStatement(sql);
                    ps.setBytes(1, Server.hashData(password));
                    ps.setBytes(2, Server.hashData(username));
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

    static SendInitData getConnectionInfo(byte[] hashedUsername) {
        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "SELECT pullableInitData FROM serverSignalCryptoData WHERE hashedUsername = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, Server.hashData(hashedUsername));
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

    static void removeConnectionInfo(byte[] hashedUsername) {
        //Executed by a user to scrub their preKeys from the server.

        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "DELETE FROM serverSignalCryptoData WHERE hashedUsername = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, Server.hashData(hashedUsername));
                ps.execute();
                conn.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static boolean userExists(byte[] hashedUsername) {

        try {
            Connection conn = GetSQLConnection.getConn();

            if (conn != null) {
                String sql = "SELECT * FROM serverSignalCryptoData WHERE hashedUsername = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, Server.hashData(hashedUsername));
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

    static boolean authenticateCredentials(byte[] username, byte[] password) {
        Connection conn = GetSQLConnection.getConn();

        try {

            if (conn != null) {
                String sql = "SELECT * FROM serverSignalCryptoData WHERE hashedUsername = ? AND hashedPassword = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setBytes(1, Server.hashData(username));
                ps.setBytes(2, Server.hashData(password));
                ResultSet rs = ps.executeQuery();
                boolean valid = rs.next();
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
