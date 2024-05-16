package entity;

import helper.security.Authentication;
import helper.security.Confidentiality;

import java.security.KeyPair;

public class UserEntity {
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private KeyPair keyPair;

    public UserEntity(String username, String password, byte[] passwordSalt, KeyPair keyPair) throws Exception {
        this.username = username;
        this.password = Authentication.hashPassword(password, passwordSalt);
        this.passwordSalt = passwordSalt;
        this.keyPair = keyPair;
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
}
