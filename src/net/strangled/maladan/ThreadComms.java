package net.strangled.maladan;


import net.MaladaN.Tor.thoughtcrime.MMessageObject;

import java.util.ArrayList;
import java.util.Vector;

//TODO Add support to store messages to be forwarded after a shutdown.
class ThreadComms {

    private static Vector<MMessageObject> messageObjects = new Vector<>();

    static boolean removeObjects(ArrayList<MMessageObject> objects) {
        return messageObjects.removeAll(objects);
    }

    static boolean removeObject(MMessageObject object) {
        return messageObjects.remove(object);
    }

    static boolean addObject(MMessageObject object) {

        if (!messageExists(object)) {
            return messageObjects.add(object);
        }
        return false;
    }

    private static boolean messageExists(MMessageObject object) {
        return messageObjects.contains(object);
    }

    static ArrayList<MMessageObject> getMessagesForClient(String actualUsername) {
        ArrayList<MMessageObject> messageObjects = new ArrayList<>();
        for (MMessageObject o : messageObjects) {
            if (o.getDestinationUser().equals(actualUsername)) {
                messageObjects.add(o);
            }
        }
        return messageObjects;
    }
}
