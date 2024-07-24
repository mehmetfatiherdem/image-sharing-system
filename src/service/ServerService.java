package service;

import helper.security.UserCertificateCredentials;

import java.util.Map;

public interface ServerService {
    void listen();
    void handleClientMessage(Map<String, String> messageKeyValues);
    void sendNotification(Map<String, String> messageKeyValues);
    void createCertificate(UserCertificateCredentials userCertificateCredentials, byte[] sign);

}
