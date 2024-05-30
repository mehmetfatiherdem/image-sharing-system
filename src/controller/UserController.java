package controller;

import model.Certificate;
import service.UserService;
import service.UserServicee;

import java.util.List;

import java.security.PublicKey;

public class UserController {
    private final UserService userService;
    private final UserServicee userServicee;

    public UserController(UserService userService, UserServicee userServicee) {
        this.userService = userService;
        this.userServicee = userServicee;
    }

    public void listenServer() {
        userServicee.listenServer();
    }

    public void listenNotifications() {
        Thread thread = new Thread(userService::listenNotifications);
        thread.start();
    }

    public void registerr(String username, String password) {
        userServicee.sendHelloMessage();
        userServicee.sendMacKey();
        userServicee.register(username, password);
    }

    public void loginn(String username, String password) {
        userServicee.sendHelloMessage();
        userServicee.sendMacKey();
        userServicee.login(username, password);
    }

    public void postImagee(String imageName, String imagePath, List<String> accessList) {
        userServicee.postImage(imageName, imagePath, accessList);
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

    public void postImage(String imageName, String imagePath, List<String> accessList) {
        userService.postImage(imageName, imagePath, accessList);
    }

    public void downloadImage(String imageName) {
        userServicee.downloadImage(imageName);
    }
}
