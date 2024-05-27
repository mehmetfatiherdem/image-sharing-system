package controller;

import model.Certificate;
import service.UserService;

import java.security.PublicKey;

public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    public void register(String username, String password) {
        userService.register(username, password);
    }

    public void login(String username, String password) {
        userService.login(username, password);
    }

    public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) {
        return userService.verifyCertificate(certificate, publicKey);
    }

    public void postImage(String imageName, String imagePath) {
        userService.postImage(imageName, imagePath);
    }

    public void downloadImage(String imageName) {
        userService.downloadImage(imageName);
    }
}
