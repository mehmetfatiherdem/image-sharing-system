package dto;

import model.Certificate;
import model.Session;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;

public class UserDTO {
    private String IP;
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private Certificate certificate;
    private KeyPair keyPair;
    private PublicKey publicKey;
    private Set<String> nonceUsed = new HashSet<>();
    private byte[] MAC;
    private Session session;


    public UserDTO(String ip) {
        this.IP = ip;
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

    public UserDTO(String username, byte[] password, byte[] passwordSalt, String IP) {
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
        this.IP = IP;
    }

    public UserDTO(String IP, String username, byte[] password, byte[] passwordSalt, Certificate certificate, KeyPair keyPair, Set<String> nonceUsed, byte[] MAC, Session session) {
        this.IP = IP;
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
        this.certificate = certificate;
        this.keyPair = keyPair;
        this.nonceUsed = nonceUsed;
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
    public String getIP() {
        return IP;
    }
    public Set<String> getNonceUsed() {
        return nonceUsed;
    }
    public void addNonceUsed(String nonce) {
        nonceUsed.add(nonce);
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
