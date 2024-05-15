package service;
import helper.image.ImageDownloadData;
import helper.image.ImageFileIO;
import helper.image.ImagePostData;
import helper.security.Auth;
import helper.security.Key;
import model.Certificate;
import model.Server;
import repository.UserRepository;

import javax.crypto.SecretKey;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final Server server;
    private final Socket socket;

    public UserServiceImpl(UserRepository userRepository, Server server, Socket socket) {
        this.userRepository = userRepository;
        this.server = server;
        this.socket = socket;
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


            try{

                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                var macKey = Key.generateMACKey();
                var mac = Key.generateMAC(imagePostData.getMessageString().getBytes(), macKey);
                var message = Key.appendMACToMessage(imagePostData.getMessageString().getBytes(), mac);

                out.writeUTF(message);

            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void downloadImage(String imageName) {

        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF("DOWNLOAD" + " " + imageName);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void retrieveImage(ImageDownloadData imageDownloadData) {

    }
}
