package service;

public interface AuthService {
    void login(String username, String password);
    void register(String username, String password);
    void logout();
}
