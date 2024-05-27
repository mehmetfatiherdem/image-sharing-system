package userlocal;

import java.util.HashSet;
import java.util.Set;

// trying to imitate users own machines to store private key and stuff
public class UserStorage {

    private String ip;
    private String userName;
    private Set<String> serverNoncesUsed = new HashSet<>();
    private static UserStorage instance;
    private byte[] serverPublicKey;
    private byte[] privateKey;
    private String sessionID;

    public UserStorage(String ip, String userName, byte[] privateKey) {
        this.ip = ip;
        this.userName = userName;
        this.privateKey = privateKey;
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

    public String getIp() {
        return ip;
    }

    public String getUserName() {
        return userName;
    }

    public String getSessionID() {
        return sessionID;
    }

    public void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }
}
