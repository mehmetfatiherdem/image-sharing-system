package model;

import helper.security.Authentication;
import helper.security.Confidentiality;

import java.security.KeyPair;

public class User {
    private String username;
    private String password;
    private byte[] passwordSalt;
    private KeyPair keyPair;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }


    public void assignSalt() {
        try {
            this.passwordSalt = Authentication.generateSalt();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void assignKeyPair() {
        try {
            this.keyPair = Confidentiality.generateRSAKeyPairs(2048);
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
    public byte[] getPasswordSalt() {
        return passwordSalt;
    }
    public void setPasswordSalt(byte[] passwordSalt) {
        this.passwordSalt = passwordSalt;
    }
    public KeyPair getKeyPair() {
        return keyPair;
    }
    public String getPassword() {
        return password;
    }
}
