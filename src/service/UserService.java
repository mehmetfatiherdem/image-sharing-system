package service;

import model.Certificate;

import java.security.PublicKey;

public interface UserService {
    boolean verifyCertificate(Certificate certificate, PublicKey publicKey);
}
