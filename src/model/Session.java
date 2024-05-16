package model;

import helper.Constants;
import helper.security.Authentication;

public class Session {
    private final String username;
    private final byte[] sharedSecret;
    private long lastAccessTime;

    public Session(String username, byte[] sharedSecret) {
        this.username = username;
        this.sharedSecret = sharedSecret;
        this.lastAccessTime = System.currentTimeMillis();
    }

    public String getUsername() {
        return username;
    }

    public boolean verifyMessageIntegrity(String message, byte[] mac) throws Exception {
        return Authentication.verifyMAC(message, mac, sharedSecret);
    }

    public void updateLastAccess() {
        this.lastAccessTime = System.currentTimeMillis();
    }

    public boolean isTimedOut() {
        long currentTime = System.currentTimeMillis();
        long sessionDuration = currentTime - lastAccessTime;
        return sessionDuration > Constants.SESSION_TIMEOUT;
    }
}
