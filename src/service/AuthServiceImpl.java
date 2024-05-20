package service;

import dto.LoginDTO;
import helper.security.Authentication;
import helper.security.Confidentiality;
import model.User;
import repository.UserRepository;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.Arrays;

public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final Socket socket;

    public AuthServiceImpl(UserRepository userRepository, Socket socket) {
        this.userRepository = userRepository;
        this.socket = socket;
    }

    @Override
    public void login(String username, String password) {

        try {
            var user = userRepository.getUser(username);
            var salt = new byte[256];

            if (user.isPresent()) {
                salt = user.get().getPasswordSalt();
            } else {
                System.out.println("User not found");
                return;
            }

            byte[] passwordHash = Authentication.hashPassword(password, salt);
            LoginDTO loginDTO = new LoginDTO(username, passwordHash);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String nonce = Authentication.generateNonce();

            var privateKey = userRepository.getPrivateKey(username);

            var signedMessage = Authentication.sign(nonce.getBytes(), privateKey.orElseThrow());

            String loginMessagePayload = "LOGIN" + " " + loginDTO.getLoginString() + " "
                    + Arrays.toString(signedMessage);

            //String loginMessage = Authentication.appendMACToMessage();

            //out.writeUTF(loginMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void register(String username, String password) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            System.out.println("ping");
            out.writeUTF("ping");

            String response = in.readUTF();
            System.out.println(response);


            /*
            User user = new User(username, password);

            byte[] passwordHash
                    = Authentication.hashPassword(password, user.getPasswordSalt());

            PublicKey publicKey = user.getKeyPair().getPublic();

            // save private key to local storage

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));


            String registerMessagePayload
                    = "REGISTER" + " " + username + " " + Arrays.toString(passwordHash)
                    + " " + Arrays.toString(user.getPasswordSalt())
                        + " " + publicKey.toString();

            String helloMsg = "HELLO";

            out.writeUTF(helloMsg);

            // wait for server to respond with its public key

            String serverPublicKeyStr = null;

            // implement waiting for server public key

            while (serverPublicKeyStr == null) {
                // wait for server to respond with its public key
                String[] serverResponse = in.readUTF().split(" ");
                if (serverResponse[0].equals("PUBLICKEY")) {
                    serverPublicKeyStr = serverResponse[1];
                }
            }

            PublicKey serverPublicKey = Confidentiality.getPublicKeyFromString(serverPublicKeyStr);

            // encrypt the message with the server's public key
            byte[] encryptedMessage = Confidentiality.encryptWithSymmetricKey(registerMessagePayload.getBytes(), serverPublicKey);

            // send the encrypted message to the server
            out.writeUTF(Arrays.toString(encryptedMessage));

             */

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void logout() {

    }
}
