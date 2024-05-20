package dto;

import model.Certificate;

import java.security.KeyPair;

public class UserDTO {
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private boolean isOnline;
    private Certificate certificate;
    private KeyPair keyPair;


    public UserDTO(String username, byte[] password) {
        this.username = username;
        this.password = password;
    }
    public UserDTO(String username, byte[] password, byte[] passwordSalt) {
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
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
    public byte[] getPassword() {
        return password;
    }
    public boolean isOnline() {
        return isOnline;
    }
    public void setOnline(boolean online) {
        isOnline = online;
    }
    public Certificate getCertificate() {
        return certificate;
    }
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

}
