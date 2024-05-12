package service;

import helper.security.Auth;
import helper.security.UserCertificateCredentials;
import repository.ServerRepository;

import java.security.PrivateKey;

public class ServerServiceImpl implements ServerService {
    private final ServerRepository serverRepository;

    public ServerServiceImpl(ServerRepository serverRepository) {
        this.serverRepository = serverRepository;
    }
    @Override
    public void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) {
        try{
            byte[] certificate = Auth.sign(userCertificateCredentials, privateKey);
            serverRepository.addCertificate(certificate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
