package helper.security;

import model.Certificate;

import java.security.*;


public class Auth {
    public static byte[] sign(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(userCertificateCredentials.getCredentialBytes());
        return signature.sign();
    }

    public static boolean verify(Certificate certificate, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initVerify(publicKey);
        sign.update(certificate.getCertificateCredentials().getCredentialBytes());
        return sign.verify(certificate.getSignature());
    }
}
