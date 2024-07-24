package dao;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import model.Certificate;
import service.ServerService;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface ServerDao {
    void saveImage(ImageMetaData metaData, ImageDownloadData imageDownloadData);
    Map<ImageMetaData, ImageDownloadData> getImageByName(String imageName);
    void saveCertificate(Certificate certificate);
    PublicKey getServerPublicKey();
    PrivateKey getServerPrivateKey();
    void addUser(UserDTO user);
    List<UserDTO> getUsers();
    UserDTO getUserWithUsername(String username);

}
