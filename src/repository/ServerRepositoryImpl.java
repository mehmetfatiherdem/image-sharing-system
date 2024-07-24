package repository;

import dao.ServerDao;
import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import model.Certificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ServerRepositoryImpl implements ServerRepository{
    private final ServerDao serverDao;

    public ServerRepositoryImpl(ServerDao serverDao) {
        this.serverDao = serverDao;
    }

    @Override
    public void saveImage(ImageMetaData metaData, ImageDownloadData imageDownloadData) {
        serverDao.saveImage(metaData, imageDownloadData);
    }
    @Override
    public Map<ImageMetaData, ImageDownloadData> getImageByName(String imageName) {
        return serverDao.getImageByName(imageName);
    }
    public void addCertificate(Certificate certificate) {
        serverDao.saveCertificate(certificate);
    }

    @Override
    public PublicKey getPublicKey() {
        return serverDao.getServerPublicKey();
    }
    @Override
    public PrivateKey getPrivateKey() {
        return serverDao.getServerPrivateKey();
    }
    @Override
    public List<UserDTO> getUsers() {
        return serverDao.getUsers();
    }

    @Override
    public void addUser(UserDTO user) {
        serverDao.addUser(user);

    }
    @Override
    public UserDTO getUserWithUsername(String username) {
        return serverDao.getUserWithUsername(username);
    }


}
