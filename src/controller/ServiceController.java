package controller;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.security.UserCertificateCredentials;
import service.ServerService;

import java.security.PrivateKey;
import java.util.ArrayList;

public class ServiceController {
    private final ServerService serverService;
    public ServiceController(ServerService serverService) {
        this.serverService = serverService;
    }

    public void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) {
        serverService.createCertificate(userCertificateCredentials, privateKey);
    }

    public void sendImagePostNotification(ArrayList<UserDTO> onlineUsers, String imageName, String ownerUsername) {
        serverService.sendImagePostNotification(onlineUsers, imageName, ownerUsername);
    }

    public void sendImage(ImageDownloadData imageDownloadData) {
        serverService.sendImage(imageDownloadData);
    }
}
