package service;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.security.UserCertificateCredentials;

import java.security.PrivateKey;
import java.util.ArrayList;

public interface ServerService {
    void createCertificate(UserCertificateCredentials userCertificateCredentials, byte[] sign, String ip);
    void sendImagePostNotification(ArrayList<UserDTO> onlineUsers, String imageName, String ownerUsername);
    void sendImage(ImageDownloadData imageDownloadData);
    void handleRequests();
}
