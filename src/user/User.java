package user;

import helper.security.Key;

import java.security.KeyPair;

public class User {
    private String username;
    private KeyPair keyPair;

    public User(String username) {
        this.username = username;

        try {
            this.keyPair = Key.generateKeyPairs(2048);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Getters and setters
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public KeyPair getKeyPair() {
        return keyPair;
    }
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
