package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageDownloadData;
import helper.image.ImageFileIO;
import helper.image.ImagePostData;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import model.Certificate;
import model.User;
import repository.UserRepository;
import userlocal.UserStorage;

import javax.crypto.SecretKey;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.util.*;

public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final Socket socket;
    private String sessionID;
    private PublicKey serverPubKey;
    private byte[] hmacK;
    private byte[] hmacGlobal;
    private String IP;

    public UserServiceImpl(UserRepository userRepository, Socket socket) {
        this.userRepository = userRepository;
        this.socket = socket;
    }

    @Override
    public void login(String username, String password) {


        try {
            var userPersistent = userRepository.getPersistentUser(username);

            if (userPersistent.isEmpty()) {
                System.out.println("User not found");
                return;
            }

            //LoginDTO loginDTO = new LoginDTO(username, Base64.getDecoder().decode(password));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            IP = userPersistent.get().getIP();

            String nonceClient = Authentication.generateNonce();
            var salt = userPersistent.get().getPasswordSalt();
            System.out.println("salt: " + Arrays.toString(salt));

            var userInMemory = userRepository.getInMemoryUserWithIP(userPersistent.get().getIP());

            System.out.println("[client] login: userinmemory: " + userInMemory.isPresent());

            User user;

            if(userInMemory.isEmpty()) {
                user = new User(userPersistent.get().getUsername(), Confidentiality.encodeByteKeyToStringBase64(userPersistent.get().getPassword()));
                user.setIP(userPersistent.get().getIP());
                userRepository.addInMemoryUser(new UserDTO(userPersistent.get().getUsername(), userPersistent.get().getPassword(), userPersistent.get().getIP()));
            } else {
                user = new User(userInMemory.get().getUsername(), Confidentiality.encodeByteKeyToStringBase64(userInMemory.get().getPassword()));
                user.setIP(userPersistent.get().getIP());
            }

            String helloMsg = Message.formatMessage("HELLO",  new HashMap<>(){{
                put("nonce", nonceClient);
                put("ip", user.getIP());
            }});

            System.out.println("[client] hello message from loginnn!!1!: " + helloMsg);

            out.writeUTF(helloMsg);

            String serverResponse = in.readUTF();

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
                            var userStorage = userRepository.getUserStorageWithIP(messageKeyValues.get("ip"));
                            userStorage.addServerNonceUsed(serverNonce);
                            if(userStorage.getServerPublicKey() == null) {
                                userStorage.setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));

                                serverPubKey = Confidentiality.getPublicKeyFromByteArray(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));

                            } else {
                                serverPubKey = Confidentiality.getPublicKeyFromByteArray(userStorage.getServerPublicKey());
                            }
                        }


                        break;
                    }
                }


            } else {
                System.out.println("Invalid message");
                System.exit(1);
            }


            //System.out.println("Server public key: " + Arrays.toString(user.getUserStorage().getServerPublicKey()));


            PublicKey serverPublicKey = Confidentiality.getPublicKeyFromByteArray(userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).getServerPublicKey());

            // send MAC key to server
            byte[] macKey = Authentication.generateMACKey();
            //byte[] pms = Confidentiality.generateAESKey(256).getEncoded();
            byte[] MAC = Authentication.generateMAC("Secretmsg123!".getBytes(), macKey);

            hmacK = macKey;
            hmacGlobal = MAC;


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPublicKey);
            String macKeyString = Message.formatMessage("MAC", new HashMap<>(){{
                put("secretMessage", "Secretmsg123!");
                put("macKey", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey));
                put("ip", user.getIP());
            }});

            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            //Thread.sleep(1000);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPublicKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);


            String loginMessagePayload = Message.formatMessage("LOGIN", new HashMap<>(){{
                put("username", username);
                put("password", Confidentiality.encodeByteKeyToStringBase64(encryptedPassword));
                put("ip", user.getIP());
                put("aesKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey));
                put("iv", Confidentiality.encodeByteKeyToStringBase64(encryptedIv));
                put("mac", Confidentiality.encodeByteKeyToStringBase64(MAC));
            }});



            out.writeUTF(loginMessagePayload);

            while (true) {
                String serverResponse2 = in.readUTF();
                var messageKeyValues2 = Message.getKeyValuePairs(serverResponse2);

                if (messageKeyValues2.get("ip").equals(user.getIP())) {
                    if(messageKeyValues2.get("message").equals("AUTHENTICATED")) {
                        var userStorage = userRepository.getUserStorageWithIP(messageKeyValues.get("ip"));
                        userStorage.setSessionID(messageKeyValues2.get("sessionID"));
                        this.sessionID = messageKeyValues2.get("sessionID");
                        System.out.println("[client] server response after login: " + messageKeyValues2.get("sessionID"));
                        break;

                    } else {
                        System.out.println("authentication failed");
                        return;
                    }

                }


            }



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
            user.assignIP();
            user.assignKeyPair();
            user.assignSalt();

            UserStorage userStorage = new UserStorage(user.getIP(), user.getUsername(), user.getKeyPair().getPrivate().getEncoded());

            userRepository.addUserStorage(userStorage);

            userRepository.addInMemoryUser(new UserDTO(user.getIP(), userStorage));

            String helloMsg = Message.formatMessage("HELLO", new HashMap<>(){{
                put("nonce", nonceClient);
                put("ip", user.getIP());
            }});

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
                            userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).addServerNonceUsed(serverNonce);
                            //user.getUserStorage().addServerNonceUsed(serverNonce);
                            userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));
                            //user.getUserStorage().setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));

                        }


                        break;
                    }
                }


            } else {
                System.out.println("Invalid message");
                System.exit(1);
            }


            //System.out.println("Server public key: " + Arrays.toString(user.getUserStorage().getServerPublicKey()));


            PublicKey serverPublicKey = Confidentiality.getPublicKeyFromByteArray(userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).getServerPublicKey());

            // send MAC key to server
            byte[] macKey = Authentication.generateMACKey();
            //byte[] pms = Confidentiality.generateAESKey(256).getEncoded();
            byte[] MAC = Authentication.generateMAC("Secretmsg123!".getBytes(), macKey);


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPublicKey);
            String macKeyString = Message.formatMessage("MAC", new HashMap<>(){{
                put("secretMessage", "Secretmsg123!");
                put("macKey", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey));
                put("ip", user.getIP());
            }});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            //Thread.sleep(1000);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPublicKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);
            var encryptedSalt = Confidentiality.encryptWithPublicKey(user.getPasswordSalt(), serverPublicKey);

            String message = Message.formatMessage("REGISTER", new HashMap<>(){{
                put("username", username);
                put("password", Confidentiality.encodeByteKeyToStringBase64(encryptedPassword));
                put("ip", user.getIP());
                put("aesKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey));
                put("iv", Confidentiality.encodeByteKeyToStringBase64(encryptedIv));
                put("mac", Confidentiality.encodeByteKeyToStringBase64(MAC));
                put("salt", Confidentiality.encodeByteKeyToStringBase64(encryptedSalt));
                put("publicKey", Base64.getEncoder().encodeToString(user.getKeyPair().getPublic().getEncoded()));
            }});


            // send the encrypted message to the server
           out.writeUTF(message);

            var userInMemory = userRepository.getInMemoryUserWithIP(user.getIP());

            if (userInMemory.isEmpty()) {
                System.out.println("User not found");
                return;
            } else {
                userInMemory.get().setUsername(username);
                userInMemory.get().setPasswordSalt(user.getPasswordSalt());

                System.out.println("[client] user salt saved: " + Arrays.toString(userInMemory.get().getPasswordSalt()));
            }

            while (true) {
               String serverResponse2 = in.readUTF();
               var messageKeyValues2 = Message.getKeyValuePairs(serverResponse2);

               if (messageKeyValues2.get("ip").equals(user.getIP())) {
                   if (messageKeyValues2.get("message").equals("CERTIFICATE")) {

                       if (messageKeyValues2.get("username").equals(user.getUsername()) &&
                               messageKeyValues2.get("publicKey").equals(user.getKeyPair().getPublic().toString())) {

                           userInMemory.get().setCertificate(new Certificate(new UserCertificateCredentials(user.getUsername(), user.getKeyPair().getPublic()),
                                   Base64.getDecoder().decode(messageKeyValues2.get("signature"))));

                           userInMemory.get().setPassword(Base64.getDecoder().decode(messageKeyValues2.get("password")));

                               userRepository.addPersistentUser(userInMemory.get());

                               System.out.println("[client] server retrieved public key and username correctly");

                               if(userRepository.getPersistentUser(user.getUsername()).isPresent()) {
                                      System.out.println("User registered to persistent users successfully");
                                   System.out.println("[client] User registered info: " +
                                           userRepository.getPersistentUser(user.getUsername()).get().getUsername()
                                           + " " + Arrays.toString(userRepository.getPersistentUser(user.getUsername()).get().getPassword()) +
                                           " salt::: " + Arrays.toString(userRepository.getPersistentUser(user.getUsername()).get().getPasswordSalt()));
                                 } else {
                                      System.out.println("User not registered");
                               }

                           break;
                       }


                   }

               }

           }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void logout() {

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
    public void postImage(String imageName, String imagePath, List<String> accessList) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            var encryptedSessionID = Confidentiality.encryptWithPublicKey(sessionID.getBytes(), serverPubKey);

            var _accessList = Message.formatListToArrayString(accessList);

            var accessMessage = Message.formatMessage("ACCESSIBILITY",
                    new HashMap<>(){{
                        put("accessList", _accessList);
                        put("sessionID", Confidentiality.encodeByteKeyToStringBase64(encryptedSessionID));
                        put("ip", IP);
                        put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));

                    }});


            out.writeUTF(accessMessage);

            while (true) {
                String res = in.readUTF();
                var messageKeyValues = Message.getKeyValuePairs(res);
                if (messageKeyValues.get("ip").equals(IP)) {
                    if (messageKeyValues.get("message").equals("SESSION_NOT_FOUND") ||
                            messageKeyValues.get("message").equals("SESSION_TIME_OUT")) {
                        break;
                    } else if (messageKeyValues.get("message").equals("SESSION_VALID")) {
                        System.out.println("[client] acked the session");
                        if (messageKeyValues.get("all") != null) {
                            System.out.println("[client] all users have access");
                        }

                    }
                }


            }

        }catch (Exception e) {
            e.printStackTrace();
        }

        /*
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

             */
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
