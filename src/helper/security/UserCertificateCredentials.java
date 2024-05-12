package helper.security;

import java.security.PublicKey;

public class UserCertificateCredentials {
    private String username;
    private PublicKey publicKey;

    public UserCertificateCredentials(String username, PublicKey publicKey) {
        this.username = username;
        this.publicKey = publicKey;
    }

    public byte[] getCredentialBytes() {
        String certificateString = username + " " + publicKey.toString();
        return certificateString.getBytes();
    }

    // Getters and setters
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public PublicKey getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
