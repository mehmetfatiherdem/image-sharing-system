package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageFileIO;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import logger.MyLogger;
import model.Certificate;
import model.User;
import repository.UserRepository;
import javax.crypto.SecretKey;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final Socket socket;
    private String sessionID;
    private volatile PublicKey serverPubKey;
    private byte[] privateKey;
    private byte[] hmacK;
    private byte[] hmacGlobal;
    private String IP;
    private String username;
    private Set<String> serverNoncesUsed = new HashSet<>();
    private final Map<String, String> accessListPublicKeys = new ConcurrentHashMap<>();

    private final Lock postImageLock = new ReentrantLock();
    private final Condition postImageCanContinue = postImageLock.newCondition();
    private boolean postImageContinue = false;
    private boolean isSessionValid = false;

    private final Lock macLock = new ReentrantLock();
    private final Condition macCanContinue = macLock.newCondition();
    private boolean macContinue = false;


    public UserServiceImpl(UserRepository userRepository, Socket socket) {
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
                if (IP == null) {
                    MyLogger.log(" RECEIVED " + message);
                } else {
                    MyLogger.log(" " + IP + " RECEIVED " + message);
                }
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
                System.out.println("[client] " + IP + " Server nonce received: " + serverNonce);

                if (serverNoncesUsed.contains(serverNonce)) {
                    System.out.println("Nonce already used replay attack alert!!!");

                } else {
                    //userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).addServerNonceUsed(serverNonce);
                    serverNoncesUsed.add(serverNonce);
                    //user.getUserStorage().addServerNonceUsed(serverNonce);
                    //userRepository.getUserStorageWithIP(messageKeyValues.get("ip")).setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));


                    setServerPubKey(Confidentiality.getPublicKeyFromString(messageKeyValues.get("publicKey")));

                    System.out.println("[client] " + IP + "Server public key received: " + serverPubKey.toString());

                    //user.getUserStorage().setServerPublicKey(Base64.getDecoder().decode(messageKeyValues.get("publicKey")));

                    macLock.lock();
                    try {
                        macContinue = true;
                        macCanContinue.signalAll();
                    } finally {
                        macLock.unlock();
                    }



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

            } else if (messageKeyValues.get("message").equals("USERNAME_TAKEN")) {

                System.out.println("[client] Username taken");

                MyLogger.log("Username taken");

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

                if (sessionID == null) {
                    System.out.println("[client] sessionID null request session notification failed");
                    return;
                }
                String m = Message.formatMessage("SESSION_NOTIFICATION", new HashMap<>(){{
                    put("sessionID", Confidentiality.encodeByteKeyToStringBase64(Confidentiality.encryptWithPublicKey(sessionID.getBytes(), getServerPubKey())));
                    put("ip", IP);
                    put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));
                }});

                out.writeUTF(m);

                if (IP == null) {
                    MyLogger.log(" SENT " + m);
                } else {
                    MyLogger.log(" " + IP + " SENT " + m);
                }

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
    public void sendHelloMessage(DataOutputStream out) {
        try {

            String nonceClient = Authentication.generateNonce();

            if (IP == null) {
                IP = Authentication.generateIP();
            }

            String helloMsg = Message.formatMessage("HELLO", new HashMap<>(){{
                put("nonce", nonceClient);
                put("ip", IP);
            }});

            System.out.println("[client] hello message: " + helloMsg);
            MyLogger.log("[client] " + IP + " " + helloMsg);

            out.writeUTF(helloMsg);

            if (IP == null) {
                MyLogger.log(" SENT " + helloMsg);
            } else {
                MyLogger.log(" " + IP + " SENT " + helloMsg);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void sendMacKey(DataOutputStream out) {
        try {

            macLock.lock();
            try {
                while (!macContinue) {
                    macCanContinue.await();
                }
            } finally {
                macLock.unlock();
            }


            // send MAC key to server
            byte[] macKey = Authentication.generateMACKey();
            //byte[] pms = Confidentiality.generateAESKey(256).getEncoded();
            byte[] MAC = Authentication.generateMAC("Secretmsg123!".getBytes(), macKey);

            hmacK = macKey;
            hmacGlobal = MAC;



            System.out.println("[client] " + IP + " MAC key generated: " + Arrays.toString(macKey));

            if (getServerPubKey() == null) {
                System.out.println("[client] " + IP + " Server public key null");

            } else {
                System.out.println("[client] " + IP + " getServerPubKey(): " + getServerPubKey().toString());

            }


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, getServerPubKey());
            String macKeyString = Message.formatMessage("MAC", new HashMap<>(){{
                put("secretMessage", "Secretmsg123!");
                put("macKey", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey));
                put("ip", IP);
            }});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            if (IP == null) {
                MyLogger.log(" SENT " + macKeyString);
            } else {
                MyLogger.log(" " + IP + " SENT " + macKeyString);
            }

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

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            sendHelloMessage(out);

            sendMacKey(out);

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
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, getServerPubKey());
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), getServerPubKey());


            String loginMessagePayload = Message.formatMessage("LOGIN", new HashMap<>(){{
                put("username", username);
                put("password", Confidentiality.encodeByteKeyToStringBase64(encryptedPassword));
                put("ip", user.getIP());
                put("aesKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey));
                put("iv", Confidentiality.encodeByteKeyToStringBase64(encryptedIv));
                put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));
            }});



            out.writeUTF(loginMessagePayload);

            if (IP == null) {
                MyLogger.log(" SENT " + loginMessagePayload);
            } else {
                MyLogger.log(" " + IP + " SENT " + loginMessagePayload);
            }

            Thread.sleep(1000);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void register(String username, String password) {
        try {

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            sendHelloMessage(out);

            sendMacKey(out);

            User user = new User(username, password);
            user.setIP(IP);
            user.assignKeyPair();
            user.assignSalt();

            this.username = username;
            this.privateKey = user.getKeyPair().getPrivate().getEncoded();

            var userDTO = new UserDTO(user.getIP()); //TODO: no user storage anymore so pass the required stuff directly

            userDTO.setUsername(username);
            userDTO.setPasswordSalt(user.getPasswordSalt());
            userDTO.setKeyPair(user.getKeyPair());

            System.out.println("[client] user salt saved: " + Arrays.toString(userDTO.getPasswordSalt()));

            userRepository.addInMemoryUser(userDTO);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, getServerPubKey());
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), getServerPubKey());
            var encryptedSalt = Confidentiality.encryptWithPublicKey(user.getPasswordSalt(), getServerPubKey());

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

            if (IP == null) {
                MyLogger.log(" SENT " + message);
            } else {
                MyLogger.log(" " + IP + " SENT " + message);
            }

            Thread.sleep(1000);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void postImage(String imageName, String imagePath, List<String> accessList) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            if (sessionID == null) {
                System.out.println("[client] sessionID null post image failed");
                return;
            }

            var encryptedSessionID = Confidentiality.encryptWithPublicKey(sessionID.getBytes(), getServerPubKey());

            var _accessList = Message.formatListToArrayString(accessList);

            var accessMessage = Message.formatMessage("ACCESSIBILITY",
                    new HashMap<>(){{
                        put("accessList", _accessList);
                        put("sessionID", Confidentiality.encodeByteKeyToStringBase64(encryptedSessionID));
                        put("ip", IP);
                        put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));

                    }});


            out.writeUTF(accessMessage);

            if (IP == null) {
                MyLogger.log(" SENT " + accessMessage);
            } else {
                MyLogger.log(" " + IP + " SENT " + accessMessage);
            }

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

                if (IP == null) {
                    MyLogger.log(" SENT " + message);
                } else {
                    MyLogger.log(" " + IP + " SENT " + message);
                }
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

            if (sessionID == null) {
                System.out.println("[client] sessionID null download image failed");
                return;
            }

            var encryptedSessionID = Confidentiality.encryptWithPublicKey(sessionID.getBytes(), getServerPubKey());

            var downloadMessage = Message.formatMessage("DOWNLOAD",
                    new HashMap<>() {{
                        put("imageName", imageName);
                        put("sessionID", Confidentiality.encodeByteKeyToStringBase64(encryptedSessionID));
                        put("ip", IP);
                        put("mac", Confidentiality.encodeByteKeyToStringBase64(hmacGlobal));

                    }});
            out.writeUTF(downloadMessage);

            if (IP == null) {
                MyLogger.log(" SENT " + downloadMessage);
            } else {
                MyLogger.log(" " + IP + " SENT " + downloadMessage);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void extractImage (Map<String, String> messageKeyValues) {
        System.out.println("[client] extracting image");
        try {
            if (messageKeyValues.get("access").equals("All") || messageKeyValues.get("access").equals(userRepository.getInMemoryUserWithIP(IP).get().getUsername())) {
                System.out.println("[client] image accessible to all");

                var decryptedAesKey = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("encryptedAESKey")),
                        userRepository.getInMemoryUserWithIP(IP).get().getKeyPair().getPrivate());
                var iv = Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("iv"));
                var encryptedImage = Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("imageBytes"));
                var decryptedImage = Confidentiality.decryptWithAES(encryptedImage, Confidentiality.getSecretKeyFromBytes(decryptedAesKey), iv);

                // verify integrity with digital signature
                var digitalSignature = Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("digitalSignature"));

                if (Authentication.verify(Confidentiality.generateMessageDigest(decryptedImage), digitalSignature, Confidentiality.getPublicKeyFromString(messageKeyValues.get("ownerPublicKey")))){
                    System.out.println("[client] image verified with signature");

                    // store the image in the folder downloads under src as png
                    // Convert byte array to BufferedImage
                    BufferedImage bufferedImage = null;
                    try (ByteArrayInputStream bais = new ByteArrayInputStream(decryptedImage)) {
                        bufferedImage = ImageIO.read(bais);
                    } catch (IOException e) {
                        e.printStackTrace();
                        return;
                    }

                    File outputDir = new File("src/downloads");

                    // Write the BufferedImage to a file in the src/downloads directory
                    File outputFile = new File(outputDir, messageKeyValues.get("imageName") + "_" + username + "_" + ".png");
                    try {
                        ImageIO.write(bufferedImage, "png", outputFile);
                        System.out.println("[client] " + IP  + " image saved to downloads folder as png in " + outputFile.getAbsolutePath());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                } else {
                    System.out.println("[client] image not verified with signature");
                }



            } else {
                System.out.println("[client] " + IP + " image not accessible to you");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public synchronized void setServerPubKey(PublicKey key) {
        this.serverPubKey = key;
    }

    public synchronized PublicKey getServerPubKey() {
        return this.serverPubKey;
    }

}
