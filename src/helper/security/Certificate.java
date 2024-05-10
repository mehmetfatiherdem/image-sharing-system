package helper.security;

public class Certificate {
    private byte[] username;
    private byte[] publicKey;

    public Certificate(byte[] username, byte[] publicKey) {
        this.username = username;
        this.publicKey = publicKey;
    }

    // Getters and setters
    public byte[] getUsername() {
        return username;
    }
    public void setUsername(byte[] username) {
        this.username = username;
    }
    public byte[] getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }
}
