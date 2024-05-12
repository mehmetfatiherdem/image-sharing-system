package service;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.security.Auth;
import helper.security.UserCertificateCredentials;
import repository.ServerRepository;

import java.security.PrivateKey;
import java.util.ArrayList;

public class ServerServiceImpl implements ServerService {
    private final ServerRepository serverRepository;

    public ServerServiceImpl(ServerRepository serverRepository) {
        this.serverRepository = serverRepository;
    }
    @Override
    public void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) {
        try{
            byte[] certificate = Auth.sign(userCertificateCredentials.getCredentialBytes(), privateKey);
            serverRepository.addCertificate(certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void sendImagePostNotification(ArrayList<UserDTO> onlineUsers, String imageName, String ownerUsername) {
        // implement this method
    }

    @Override
    public void sendImage(ImageDownloadData imageDownloadData) {
        // TODO: implement this method
    }
}
