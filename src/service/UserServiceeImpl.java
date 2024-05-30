package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageFileIO;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UserServiceeImpl implements UserServicee {

    private final UserRepository userRepository;
    private final Socket socket;
    private String sessionID;
    private PublicKey serverPubKey;
    private byte[] hmacK;
    private byte[] hmacGlobal;
    private String IP;
    private Set<String> serverNoncesUsed = new HashSet<>();
    private final Map<String, String> accessListPublicKeys = new ConcurrentHashMap<>();

    private final Lock postImageLock = new ReentrantLock();
    private final Condition postImageCanContinue = postImageLock.newCondition();
    private boolean postImageContinue = false;
    private boolean isSessionValid = false;


    public UserServiceeImpl(UserRepository userRepository, Socket socket) {
        this.userRepository = userRepository;
        this.socket = socket;
    }

    @Override
    public void listenServer() {
        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            System.out.println("[client] Listening for messages");

            while (true) {
                String message = in.readUTF();
                var messageKeyValues = Message.getKeyValuePairs(message);

                handleServerMessage(messageKeyValues);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void handleServerMessage(Map<String, String> messageKeyValues) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            System.out.println("[client] handling server messages");

            if (messageKeyValues.get("message").equals("PUBLICKEY")) {
                var serverNonce = messageKeyValues.get("nonce");
                System.out.println("[client] Server nonce received: " + serverNonce);

                if (serverNoncesUsed.contains(serverNonce)) {
                    System.out.println("Nonce already used replay attack alert!!!");

                } else {
                    //userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).addServerNonceUsed(serverNonce);
                    serverNoncesUsed.add(serverNonce);
                    //user.getUserStorage().addServerNonceUsed(serverNonce);
                    //userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));
                    serverPubKey = Confidentiality.getPublicKeyFromByteArray(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));
                    //user.getUserStorage().setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));
/*
                    macLock.lock();
                    try {
                        macContinue = true;
                        macCanContinue.signalAll();
                    } finally {
                        macLock.unlock();
                    }

 */

                }

            } else if (messageKeyValues.get("message").equals("MAC_RECEIVED")) {
                System.out.println("[client] Server received MAC key");
                /*
                registerLock.lock();
                try {
                    registerContinue = true;
                    registerCanContinue.signalAll();
                } finally {
                    registerLock.unlock();
                }

                 */

            } else if (messageKeyValues.get("message").equals("CERTIFICATE")) {

                var inMemoryUser = userRepository.getInMemoryUserWithIP(IP).orElseThrow();

                if (messageKeyValues.get("username").equals(inMemoryUser.getUsername()) &&
                        messageKeyValues.get("publicKey").equals(inMemoryUser.getKeyPair().getPublic().toString())) {

                    inMemoryUser.setCertificate(new Certificate(new UserCertificateCredentials(inMemoryUser.getUsername(), inMemoryUser.getKeyPair().getPublic()),
                            Base64.getDecoder().decode(messageKeyValues.get("signature"))));

                    inMemoryUser.setPassword(Base64.getDecoder().decode(messageKeyValues.get("password")));

                    userRepository.addPersistentUser(inMemoryUser);

                    System.out.println("[client] server retrieved public key and username correctly");

                    if(userRepository.getPersistentUser(inMemoryUser.getUsername()).isPresent()) {

                        System.out.println("User registered to persistent users successfully");
                        System.out.println("[client] User registered info: " + userRepository.getPersistentUser(inMemoryUser.getUsername()).get().getUsername()
                            + " " + Arrays.toString(userRepository.getPersistentUser(inMemoryUser.getUsername()).get().getPassword())
                        );
                    } else {
                        System.out.println("User not registered");
                    }


                }


            } else if(messageKeyValues.get("message").equals("AUTHENTICATED")) {
                var userStorage = userRepository.getUserStorageWithIP(IP);
                userStorage.setSessionID(messageKeyValues.get("sessionID"));
                this.sessionID = messageKeyValues.get("sessionID");
                System.out.println("[client] server response after login: " + messageKeyValues.get("sessionID"));


            } else if (messageKeyValues.get("message").equals("SESSION_NOT_FOUND") ||
                    messageKeyValues.get("message").equals("SESSION_TIME_OUT")) {
                System.out.println("[client] session not found or timed out");
                postImageLock.lock();
                try {
                    isSessionValid = false;
                    postImageContinue = true;
                    postImageCanContinue.signalAll();
                } finally {
                    postImageLock.unlock();
                }

            } else if (messageKeyValues.get("message").equals("SESSION_VALID")) {
                System.out.println("[client] session valid");



                for (var kV : messageKeyValues.entrySet()) {
                    if (!kV.getKey().equals("message") && !kV.getKey().equals("ip")) {
                        accessListPublicKeys.put(kV.getKey(), kV.getValue());
                    }
                }


                postImageLock.lock();
                try {
                    isSessionValid = true;
                    postImageContinue = true;
                    postImageCanContinue.signalAll();
                } finally {
                    postImageLock.unlock();
                }

            } else if (messageKeyValues.get("message").equals("REQUEST_SESSION_NOTIFICATION")) {
                System.out.println("[client] request session notification received");
                out.writeUTF(Message.formatMessage("SESSION_NOTIFICATION", new HashMap<>(){{
                    put("sessionID", Confidentiality.encodeByteKeyToStringBase64(Confidentiality.encryptWithPublicKey(sessionID.getBytes(), serverPubKey)));
                    put("ip", IP);
                }}));

            } else if (messageKeyValues.get("message").equals("SESSION_NOT_FOUND_NOTIFICATION") ||
                    messageKeyValues.get("message").equals("SESSION_TIME_OUT_NOTIFICATION")) {
                System.out.println("[client] session not found or timed out notification");

            } else if (messageKeyValues.get("message").equals("NEW_IMAGE")) {
                System.out.println("[client] ip: " + IP + " new image notification: " + messageKeyValues.get("imageName") + " from " + messageKeyValues.get("owner"));

            } else if (messageKeyValues.get("message").equals("DOWNLOAD_IMAGE")) {

                extractImage(messageKeyValues);
            }
            else {
                System.out.println("[client] unknown message from server");
            }



        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void sendHelloMessage() {
        try {

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            String nonceClient = Authentication.generateNonce();

            if (IP == null) {
                IP = Authentication.generateIP();
            }

            String helloMsg = Message.formatMessage("HELLO", new HashMap<>(){{
                put("nonce", nonceClient);
                put("ip", IP);
            }});

            System.out.println("[client] hello message: " + helloMsg);

            out.writeUTF(helloMsg);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void sendMacKey() {
        try {
            /*
            macLock.lock();
            try {
                while (!macContinue) {
                    macCanContinue.await();
                }
            } finally {
                macLock.unlock();
            }

             */

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // send MAC key to server
            byte[] macKey = Authentication.generateMACKey();
            //byte[] pms = Confidentiality.generateAESKey(256).getEncoded();
            byte[] MAC = Authentication.generateMAC("Secretmsg123!".getBytes(), macKey);

            hmacK = macKey;
            hmacGlobal = MAC;


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPubKey);
            String macKeyString = Message.formatMessage("MAC", new HashMap<>(){{
                put("secretMessage", "Secretmsg123!");
                put("macKey", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey));
                put("ip", IP);
            }});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

        } catch (Exception e) {
            e.printStackTrace();
        }
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

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPubKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPubKey);


            String loginMessagePayload = Message.formatMessage("LOGIN", new HashMap<>(){{
                put("username", username);
                put("password", Confidentiality.encodeByteKeyToStringBase64(encryptedPassword));
                put("ip", user.getIP());
                put("aesKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey));
                put("iv", Confidentiality.encodeByteKeyToStringBase64(encryptedIv));
                put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));
            }});



            out.writeUTF(loginMessagePayload);

            Thread.sleep(1000);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void register(String username, String password) {
        try {

            /*
            registerLock.lock();
            try {
                while (!registerContinue) {
                    registerCanContinue.await();
                }
            } finally {
                registerLock.unlock();
            }

             */

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            User user = new User(username, password);
            user.setIP(IP);
            user.assignKeyPair();
            user.assignSalt();

            UserStorage userStorage = new UserStorage(user.getIP(), user.getUsername(), user.getKeyPair().getPrivate().getEncoded());

            userRepository.addUserStorage(userStorage);

            var userDTO = new UserDTO(user.getIP(), userStorage);

            userDTO.setUsername(username);
            userDTO.setPasswordSalt(user.getPasswordSalt());
            userDTO.setKeyPair(user.getKeyPair());

            System.out.println("[client] user salt saved: " + Arrays.toString(userDTO.getPasswordSalt()));

            userRepository.addInMemoryUser(userDTO);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPubKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPubKey);
            var encryptedSalt = Confidentiality.encryptWithPublicKey(user.getPasswordSalt(), serverPubKey);

            String message = Message.formatMessage("REGISTER", new HashMap<>(){{
                put("username", username);
                put("password", Confidentiality.encodeByteKeyToStringBase64(encryptedPassword));
                put("ip", user.getIP());
                put("aesKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey));
                put("iv", Confidentiality.encodeByteKeyToStringBase64(encryptedIv));
                put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));
                put("salt", Confidentiality.encodeByteKeyToStringBase64(encryptedSalt));
                put("publicKey", Base64.getEncoder().encodeToString(user.getKeyPair().getPublic().getEncoded()));
            }});


            // send the encrypted message to the server
            out.writeUTF(message);

            Thread.sleep(1000);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void postImage(String imageName, String imagePath, List<String> accessList) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

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

            postImageLock.lock();
            try {
                while (!postImageContinue) {
                    postImageCanContinue.await();
                }
            } finally {
                postImageContinue = false;
                postImageLock.unlock();
            }

            if (!isSessionValid) {
                System.out.println("[client] session not valid post image failed");
                return;
            }

            ImageFileIO imageFileIO = new ImageFileIO(imagePath);
            byte[] imageBytes = imageFileIO.getImageBytes();
            SecretKey aesKey = Confidentiality.generateAESKey(256);

            byte[] iv = Confidentiality.generateIV(16);
            byte[] encryptedImageBytes = Confidentiality.encryptWithAES(imageBytes, aesKey, iv);

            // hash and sign the image
            byte[] imageHash = Confidentiality.generateMessageDigest(imageBytes);

            var privateKey = userRepository.getUserStorageWithIP(IP).getPrivateKey();

            if (privateKey == null){
                System.out.println("[client] no private key found for user");

            } else {
                byte[] digitalSignature = Authentication.sign(imageHash, Confidentiality.getPrivateKeyFromByteArray(privateKey));

                HashMap<String, String> msg = new HashMap<>(){{
                    put("imageName", imageName);
                    put("imageBytes", Confidentiality.encodeByteKeyToStringBase64(encryptedImageBytes));
                    put("digitalSignature", Confidentiality.encodeByteKeyToStringBase64(digitalSignature));
                    put("iv", Confidentiality.encodeByteKeyToStringBase64(iv));
                    put("sessionID", Confidentiality.encodeByteKeyToStringBase64(encryptedSessionID));
                    put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));
                    put("ip", IP);
                }};

                for (var kV : accessListPublicKeys.entrySet()) {

                    byte[] kvByte = Confidentiality.decodeStringKeyToByteBase64(kV.getValue());
                    PublicKey publicKey = Confidentiality.getPublicKeyFromByteArray(kvByte);
                    byte[] encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), publicKey);
                    String aesEnc = Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey);
                    msg.put(kV.getKey(), aesEnc);
                }

                String message = Message.formatMessage("POST_IMAGE", msg);

                out.writeUTF(message);
            }

            Thread.sleep(1000);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void downloadImage(String imageName) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            var encryptedSessionID = Confidentiality.encryptWithPublicKey(sessionID.getBytes(), serverPubKey);

            var downloadMessage = Message.formatMessage("DOWNLOAD",
                    new HashMap<>() {{
                        put("imageName", imageName);
                        put("sessionID", Confidentiality.encodeByteKeyToStringBase64(encryptedSessionID));
                        put("ip", IP);
                        put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));

                    }});
            out.writeUTF(downloadMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void extractImage (Map<String, String> messageKeyValues) {
        System.out.println("[client] extracting image");
        try {
            if (messageKeyValues.get("access").equals("All")) {
                System.out.println("[client] image accessible to all");
            } else {
                System.out.println("[client] image accessible to: " + messageKeyValues.get("access"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
