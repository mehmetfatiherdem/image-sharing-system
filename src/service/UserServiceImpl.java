package service;
import helper.image.ImageDownloadData;
import helper.image.ImageFileIO;
import helper.image.ImagePostData;
import helper.security.Auth;
import helper.security.Key;
import model.Certificate;
import repository.UserRepository;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public boolean verifyCertificate(Certificate certificate, PublicKey publicKey) {
        boolean isVerified = false;

        try {
            isVerified = Auth.verify(certificate.getCertificateCredentials().getCredentialBytes(), certificate.getSignature(), publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return isVerified;
    }

    @Override
    public void postImage(String imageName, String imagePath, PublicKey serverPublicKey, PrivateKey userPrivateKey) {
        try {
            ImageFileIO imageFileIO = new ImageFileIO(imagePath);
            byte[] imageBytes = imageFileIO.getImageBytes();
            SecretKey aesKey = Key.generateAESKey(256);

            byte[] iv = Key.generateIV(16);
            byte[] encryptedImageBytes = Key.encryptWithAES(imageBytes, aesKey, iv);

            // hash and sign the image
            byte[] imageHash = Key.generateMessageDigest(encryptedImageBytes);
            byte[] digitalSignature = Auth.sign(imageHash, userPrivateKey);

            // encrypt the AES key with the server's public key
            byte[] encryptedAESKey = Key.encryptWithSymmetricKey(aesKey.getEncoded(), serverPublicKey);

            ImagePostData imagePostData = new ImagePostData(imageName, encryptedImageBytes, digitalSignature, encryptedAESKey, iv);

            //FIXME: not sure how to handle post image since it will be done through sockets
            // maybe we can create a task to sen the byte via socket and pass the imagePostData as a parameter
            // call that task here in a thread

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void downloadImage(String imageName) {
        // TODO: implement this method
    }

    @Override
    public void retrieveImage(ImageDownloadData imageDownloadData) {

    }
}
