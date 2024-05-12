package controller;

import helper.image.ImagePostData;
import model.Certificate;
import service.UserService;

import java.security.PrivateKey;
import java.security.PublicKey;

public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) {
        return userService.verifyCertificate(certificate, publicKey);
    }

    public void postImage(String imageName, String imagePath, PublicKey serverPublicKey, PrivateKey userPrivateKey) {
        userService.postImage(imageName, imagePath, serverPublicKey, userPrivateKey);
    }

    public void downloadImage(String imageName) {
        userService.downloadImage(imageName);
    }
}
