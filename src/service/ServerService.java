package service;

import helper.security.UserCertificateCredentials;

import java.security.PrivateKey;

public interface ServerService {
    void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey);
}
