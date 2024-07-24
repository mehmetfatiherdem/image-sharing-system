package repository;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface ServerRepository {
    void saveImage(ImageMetaData metaData, ImageDownloadData imageDownloadData);
    Map<ImageMetaData, ImageDownloadData> getImageByName(String imageName);
    void addCertificate(Certificate certificate);
    PublicKey getPublicKey();
    PrivateKey getPrivateKey();
    List<UserDTO> getUsers();
    void addUser(UserDTO user);
    UserDTO getUserWithUsername(String username);
}
