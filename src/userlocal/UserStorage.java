package userlocal;

import java.util.HashSet;
import java.util.Set;

// trying to imitate users own machines to store private key and stuff
public class UserStorage {

    private Set<String> serverNoncesUsed = new HashSet<>();
    private static UserStorage instance;
    private byte[] serverPublicKey;
    private byte[] privateKey;

    public UserStorage() {
    }

    public static UserStorage getInstance() {
        if (instance == null) {
            instance = new UserStorage();
        }
        return instance;
    }

    // Getters and setters
    public byte[] getServerPublicKey() {
        return serverPublicKey;
    }
    public void setServerPublicKey(byte[] serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }
    public byte[] getPrivateKey() {
        return privateKey;
    }
    public void setPrivateKey(byte[] privateKey) {
        this.privateKey = privateKey;
    }
    public Set<String> getServerNoncesUsed() {
        return serverNoncesUsed;
    }
    public void addServerNonceUsed(String nonce) {
        serverNoncesUsed.add(nonce);
    }

}
