package service;

import dto.LoginDTO;
import dto.UserDTO;
import helper.format.Message;
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
import java.util.Base64;

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

            // FIXME: encrypt the pword with server's public key hash it on the server side

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

            String nonceClient = Authentication.generateNonce();

            User user = new User(username, password);

            userRepository.addUser(new UserDTO(user.getIP(), user.getUserStorage()));

            String helloMsg = Message.formatMessage("HELLO", new String[]{"nonce", "ip"},
                    new String[]{nonceClient, user.getIP()});

            System.out.println("[client] hello message: " + helloMsg);

            out.writeUTF(helloMsg);

            String serverResponse = in.readUTF();

            PublicKey publicKey = user.getKeyPair().getPublic();


            var messageKeyValues = Message.getKeyValuePairs(serverResponse);


            if (messageKeyValues.get("message").equals("PUBLICKEY")) {

                while (true) {
                    System.out.println("looking for message with my ip: " + user.getIP());
                    if (messageKeyValues.get("ip").equals(user.getIP())) {
                        var serverNonce = messageKeyValues.get("nonce");
                        System.out.println("[client] Server nonce received: " + serverNonce);

                        if (userRepository.getServerNonces(user.getIP()) != null &&
                                userRepository.getServerNonces(user.getIP()).contains(serverNonce)) {
                            System.out.println("Nonce already used replay attack alert!!!");

                        }else {
                            user.getUserStorage().addServerNonceUsed(serverNonce);
                            user.getUserStorage().setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));

                        }


                        break;
                    }
                }


            } else {
                System.out.println("Invalid message");
                System.exit(1);
            }


            //System.out.println("Server public key: " + Arrays.toString(user.getUserStorage().getServerPublicKey()));


            PublicKey serverPublicKey = Confidentiality.getPublicKeyFromByteArray(user.getUserStorage().getServerPublicKey());

            // send MAC key to server
            byte[] macKey = Authentication.generateMACKey();
            //byte[] pms = Confidentiality.generateAESKey(256).getEncoded();
            byte[] MAC = Authentication.generateMAC("Secretmsg123!".getBytes(), macKey);


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPublicKey);
            String macKeyString = Message.formatMessage("MAC", new String[]{"secretMessage", "macKey", "ip"},
                    new String[]{"Secretmsg123!", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey), user.getIP()});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            Thread.sleep(1000);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPublicKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);

            String message = Message.formatMessage("REGISTER", new String[]{"username", "password", "salt", "publicKey", "mac", "ip", "aesKey", "iv"},
                    new String[]{username, password, Confidentiality.encodeByteKeyToStringBase64(user.getPasswordSalt()),
                            Confidentiality.encodeByteKeyToStringBase64(user.getKeyPair().getPublic().getEncoded()),
                                Confidentiality.encodeByteKeyToStringBase64(MAC), user.getIP(),
                                Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey), Confidentiality.encodeByteKeyToStringBase64(encryptedIv)});



            // send the encrypted message to the server
           out.writeUTF(message);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void logout() {

    }
}
