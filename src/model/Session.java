package model;

import helper.Constants;
import helper.security.Authentication;

public class Session {
    private final String sessionID;
    private final String username;
    private long lastAccessTime;

    public Session(String username) {
        this.sessionID = Authentication.generateSessionID();
        this.username = username;
        this.lastAccessTime = System.currentTimeMillis();
    }

    public void updateLastAccess() {
        this.lastAccessTime = System.currentTimeMillis();
    }

    public boolean isTimedOut() {
        long currentTime = System.currentTimeMillis();
        long sessionDuration = currentTime - lastAccessTime;
        return sessionDuration > Constants.SESSION_TIMEOUT;
    }

    public String getUsername() {
        return username;
    }
    public String getSessionID(){
        return sessionID;
    }
    public long getLastAccessTime() {
        return lastAccessTime;
    }


}
