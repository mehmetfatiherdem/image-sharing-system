import helper.security.Authentication;
import helper.security.Confidentiality;
import model.Server;

import java.net.BindException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws Exception {
       ApplicationManager.getInstance().run();
        /*
        Server server = Server.getInstance(1233);
        byte[] macKey = Authentication.generateMACKey();
        PublicKey serverPublicKey = Confidentiality.getPublicKeyFromByteArray(server.getServerStorage().getPublicKey());
        String macKeyString = "MAC" + " " + "Secretmsg123!" + Arrays.toString(macKey);
        var encrypted = Confidentiality.encryptWithPublicKey(macKeyString.getBytes(), serverPublicKey);
        */
    }
}