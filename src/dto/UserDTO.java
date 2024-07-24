package dto;

import model.Certificate;
import model.Session;

import java.security.KeyPair;
import java.security.PublicKey;

public class UserDTO {
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private Certificate certificate;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private byte[] MAC;
    private Session session;

    public UserDTO() {
    }
    public UserDTO(String username, byte[] password) {
        this.username = username;
        this.password = password;
    }

    public UserDTO(String username, byte[] password, byte[] passwordSalt) {
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
    }

    public UserDTO(String username, byte[] password, byte[] passwordSalt, Certificate certificate, KeyPair keyPair, byte[] MAC, Session session) {
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
        this.certificate = certificate;
        this.keyPair = keyPair;
        this.MAC = MAC;
        this.session = session;
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
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }
    public byte[] getPassword() {
        return password;
    }
    public Certificate getCertificate() {
        return certificate;
    }
    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }
    public byte[] getMAC() {
        return MAC;
    }
    public void setMAC(byte[] MAC) {
        this.MAC = MAC;
    }
    public Session getSession() {
        return session;
    }
    public void setSession(Session session) {
        this.session = session;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
