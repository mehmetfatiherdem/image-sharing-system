package server;

import java.security.KeyPair;
import java.security.PublicKey;

public class Server {
    private KeyPair keyPair;

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }
}
