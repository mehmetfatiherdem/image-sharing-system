package user;

import helper.security.Key;

import java.security.KeyPair;

public class User {
    private String username;
    private KeyPair keyPair; // let's encapsulate the key pair in the user class

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

}
