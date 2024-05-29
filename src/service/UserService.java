package service;

import helper.image.ImageDownloadData;
import model.Certificate;

import java.security.PublicKey;
import java.util.List;

public interface UserService {
    void login(String username, String password);
    void register(String username, String password);
    void logout();
    boolean verifyCertificate(Certificate certificate, PublicKey publicKey);
    void postImage(String imageName, String imagePath, List<String> accessList);
    void downloadImage(String imageName);
    void retrieveImage(ImageDownloadData imageDownloadData);
    void listenNotifications();
}
