package service;

import helper.image.ImageDownloadData;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface UserService {
    boolean verifyCertificate(Certificate certificate, PublicKey publicKey);
    void postImage(String imageName, String imagePath, PublicKey serverPublicKey, PrivateKey userPrivateKey);
    void downloadImage(String imageName);
    void retrieveImage(ImageDownloadData imageDownloadData);
}
