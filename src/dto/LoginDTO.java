package dto;

import java.util.Arrays;

public class LoginDTO {
    private String username;
    private byte[] passwordHash;

    public LoginDTO(String username, byte[] passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
    }

    public String getLoginString() {
        return username + " " + Arrays.toString(passwordHash);
    }

    // Getters
    public String getUsername() {
        return username;
    }

    public byte[] getPasswordHash() {
        return passwordHash;
    }
}
