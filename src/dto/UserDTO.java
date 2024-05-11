package dto;

public class UserDTO {
    private String username;
    private boolean isOnline;

    public UserDTO(String username) {
        this.username = username;
    }

    public UserDTO(String username, boolean isOnline) {
        this.username = username;
        this.isOnline = isOnline;
    }

    // Getters and setters
    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public boolean isOnline() {
        return isOnline;
    }
    public void setOnline(boolean isOnline) {
        this.isOnline = isOnline;
    }
}
