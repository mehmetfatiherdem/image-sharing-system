package controller;

import service.AuthService;

public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    public void register(String username, String password) {
        authService.register(username, password);
    }

    public void login(String username, String password) {
        authService.login(username, password);
    }
}
