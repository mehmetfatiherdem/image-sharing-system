package entity;

import model.Certificate;

public class UserEntity {
    private String username;
    private byte[] password;
    private byte[] passwordSalt;
    private Certificate certificate;

    public UserEntity(String username, byte[] password, byte[] passwordSalt, Certificate certificate) throws Exception {
        this.username = username;
        this.password = password;
        this.passwordSalt = passwordSalt;
        this.certificate = certificate;
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
    public Certificate getCertificate() {
        return certificate;
    }
    public byte[] getPassword() {
        return password;
    }
}
