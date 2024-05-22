package service;
import helper.image.ImageDownloadData;
import helper.image.ImageFileIO;
import helper.image.ImagePostData;
import helper.security.Authentication;
import helper.security.Confidentiality;
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
            isVerified = Authentication.verify(certificate.getCertificateCredentials().getCredentialBytes(), certificate.getSignature(), publicKey);
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
            SecretKey aesKey = Confidentiality.generateAESKey(256);

            byte[] iv = Confidentiality.generateIV(16);
            byte[] encryptedImageBytes = Confidentiality.encryptWithAES(imageBytes, aesKey, iv);

            // hash and sign the image
            byte[] imageHash = Confidentiality.generateMessageDigest(encryptedImageBytes);
            byte[] digitalSignature = Authentication.sign(imageHash, userPrivateKey);

            // encrypt the AES key with the server's public key
            byte[] encryptedAESKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);

            ImagePostData imagePostData = new ImagePostData(imageName, encryptedImageBytes, digitalSignature, encryptedAESKey, iv);


            try{

                DataOutputStream out = new DataOutputStream(socket.getOutputStream());

                var macKey = Authentication.generateMACKey();
                var mac = Authentication.generateMAC(imagePostData.getMessageString().getBytes(), macKey);

                //FIXME: we changed message format to json-like so change this
                var message = Authentication.appendMACToMessage(imagePostData.getMessageString().getBytes(), mac);

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
