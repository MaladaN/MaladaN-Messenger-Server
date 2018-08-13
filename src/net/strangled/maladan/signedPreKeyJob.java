package net.strangled.maladan;

import net.MaladaN.Tor.thoughtcrime.InitStore;
import net.MaladaN.Tor.thoughtcrime.SendInitData;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;

public class signedPreKeyJob implements Job {

    @Override
    public void execute(JobExecutionContext jobExecutionContext) {
        SendInitData serverData = GetServerSQLConnectionAndHandle.getConnectionInfo("SERVER");
        //retrieve our identity key pair (for the server)
        IdentityKeyPair serverPair = InitStore.getIdentityKeyPair();

        if (serverPair != null && serverData != null) {
            //Generate a new signed pre-key for the server, and apply it to the server's signal data.
            try {
                System.out.println("Updating Server signed pre key.");
                SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(serverPair, 5);
                serverData.updateSignedPreKey(signedPreKey);
                GetServerSQLConnectionAndHandle.updateConnectionInfo(serverData, "SERVER");

            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("An error occurred creating a new signed pre-key for the server.");
        }
    }
}
