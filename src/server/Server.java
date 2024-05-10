package server;

import java.security.KeyPair;

public class Server {
    private KeyPair keyPair;

    // Getters and setters
    public KeyPair getKeyPair() {
        return keyPair;
    }
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
