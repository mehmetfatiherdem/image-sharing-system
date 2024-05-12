package controller;

import helper.security.UserCertificateCredentials;
import service.ServerService;

import java.security.PrivateKey;

public class ServiceController {
    private final ServerService serverService;
    public ServiceController(ServerService serverService) {
        this.serverService = serverService;
    }

    public void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) {
        serverService.createCertificate(userCertificateCredentials, privateKey);
    }
}
