package controller;

import model.Certificate;
import service.UserService;

import java.security.PublicKey;

public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) {
        return userService.verifyCertificate(certificate, publicKey);
    }
}
