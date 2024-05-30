package dao;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface ServerDao {
    void saveImage(ImageMetaData metaData, ImageDownloadData imageDownloadData);
    Map<ImageMetaData, ImageDownloadData> getImageByName(String imageName);
    void saveCertificate(Certificate certificate, String ip);
    PublicKey getServerPublicKey();
    PrivateKey getServerPrivateKey();
    Set<String> getNoncesUsed(String ip);
    void addNonceUsed(String ip, String nonce);
    void addUser(UserDTO user);
    List<UserDTO> getUsers();
    UserDTO getUserWithIP(String ip);
    UserDTO getUserWithUsername(String username);

}
