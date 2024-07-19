package controller;

import service.UserService;

import java.util.List;

public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    public void listenServer() {
        userService.listenServer();
    }

    public void register(String username, String password) {
        //userService.sendHelloMessage();
        //userService.sendMacKey();
        userService.register(username, password);
    }

    public void login(String username, String password) {
       // userService.sendHelloMessage();
        //userService.sendMacKey();
        userService.login(username, password);
    }

    public void postImage(String imageName, String imagePath, List<String> accessList) {
        userService.postImage(imageName, imagePath, accessList);
    }

    public void downloadImage(String imageName) {
        userService.downloadImage(imageName);
    }
}
