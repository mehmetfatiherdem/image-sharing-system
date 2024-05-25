package dto;

import model.Certificate;
import userlocal.UserStorage;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserDTO {
    private String IP;
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private boolean isOnline;
    private Certificate certificate;
    private KeyPair keyPair;
    private Set<String> noncesUsed = new HashSet<>();
    private UserStorage userStorage;


    public UserDTO(String ip) {
        this.IP = ip;
    }
    public UserDTO(String ip, UserStorage userStorage) {
        this.IP = ip;
        this.userStorage = userStorage;
    }
    public UserDTO(String username, byte[] password) {
        this.username = username;
        this.password = password;
    }
    public UserDTO(String username, byte[] password, String IP) {
        this.username = username;
        this.password = password;
        this.IP = IP;
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
    public void setPassword(byte[] password) {
        this.password = password;
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
    public void setIP(String IP) {
        this.IP = IP;
    }
    public String getIP() {
        return IP;
    }
    public Set<String> getNoncesUsed() {
        return noncesUsed;
    }
    public void addNonceUsed(String nonce) {
        noncesUsed.add(nonce);
    }
    public UserStorage getUserStorage() {
        return userStorage;
    }
    public void setUserStorage(UserStorage userStorage) {
        this.userStorage = userStorage;
    }
}
