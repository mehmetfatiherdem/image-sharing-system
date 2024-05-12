package model;

import helper.security.UserCertificateCredentials;

public class Certificate {
    private final UserCertificateCredentials userCertificateCredentials;
    private final byte[] signature;

    public Certificate(UserCertificateCredentials userCertificateCredentials, byte[] signature) {
        this.userCertificateCredentials = userCertificateCredentials;
        this.signature = signature;
    }

    // Getters
    public UserCertificateCredentials getCertificateCredentials() {
        return userCertificateCredentials;
    }

    public byte[] getSignature() {
        return signature;
    }
}
