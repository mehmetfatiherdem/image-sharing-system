package model;

import helper.security.Authentication;
import helper.security.Confidentiality;
import userlocal.UserStorage;

import java.security.KeyPair;

public class User {
    private String username;
    private String password;
    private byte[] passwordSalt;
    private KeyPair keyPair;
    private UserStorage userStorage;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
        try {
            this.passwordSalt = Authentication.generateSalt();
            this.keyPair = Confidentiality.generateRSAKeyPairs(2048);
        } catch (Exception e) {
            e.printStackTrace();
        }

        userStorage = UserStorage.getInstance();
        userStorage.setPrivateKey(Confidentiality.getByteArrayFromPrivateKey(keyPair.getPrivate()));
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
    public UserStorage getUserStorage() {
        return userStorage;
    }
    public void setUserStorage(UserStorage userStorage) {
        this.userStorage = userStorage;
    }

}
