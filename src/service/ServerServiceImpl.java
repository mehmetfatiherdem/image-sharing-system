package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import logger.MyLogger;
import model.Certificate;
import model.Server;
import model.Session;
import repository.ServerRepository;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ServerServiceImpl implements ServerService, Runnable{

    private ServerRepository serverRepository;

    // moving the server storage here
    // *****************
    private Set<String> nonceUsed = new HashSet<>();
    private byte[] macKey;
    private byte[] MAC;
    // *****************
    private Socket socket;
    private final Lock sendNotificationLock = new ReentrantLock();
    private final Condition sendNotificationCondition = sendNotificationLock.newCondition();
    private boolean sendNotificationContinue = false;

    public ServerServiceImpl(ServerRepository serverRepository, Socket socket) {
        this.serverRepository = serverRepository;
        this.socket = socket;
    }

    @Override
    public void createCertificate(UserCertificateCredentials userCertificateCredentials, byte[] sign) {
        try{
            //byte[] certificate = Authentication.sign(userCertificateCredentials.getCredentialBytes(), privateKey);
            serverRepository.addCertificate(new Certificate(userCertificateCredentials, sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void listen() {
        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

            System.out.println("[server] Listening for messages");

            while (true) {
                String message = in.readUTF();

                MyLogger.log("[server] message received: " + message);

                var messageKeyValues = Message.getKeyValuePairs(message);

                handleClientMessage(messageKeyValues);
            }
        }catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void handleClientMessage(Map<String, String> messageKeyValues) {

        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            System.out.println("[server] handling client messages");

            if (messageKeyValues.get("message").equals("HELLO")) {
                if (nonceUsed.contains(messageKeyValues.get("nonce"))) {
                    System.out.println("[server] Nonce already used REPLAY ATTACK ALERT!!!: " + messageKeyValues.get("nonce"));

                } else {
                    String nonceServer = Authentication.generateNonce();

                    //FIXME: we are removing nonce data from serverRepository and adding it here so if any nonce value with
                    // ip check you see, try to fix it by using nonceUsed local var from here.

                    // serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));
                    nonceUsed.add(messageKeyValues.get("nonce"));

                    /*
                    for (var msg : messageKeyValues.entrySet()) {
                        System.out.println("[server] key: " + msg.getKey() + " value: " + msg.getValue());
                    }

                     */

                    // serverRepository.addUser(new UserDTO(messageKeyValues.get("ip")));
                    // serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));


                    System.out.println("[server] Nonce added to list: " + messageKeyValues.get("nonce"));
                    // System.out.println("[server] ip: " + messageKeyValues.get("ip"));


                    String publicKeyMessage = Message.formatMessage("PUBLICKEY", new HashMap<>() {{
                        put("publicKey", Confidentiality.encodeByteKeyToStringBase64(serverRepository.getPublicKey().getEncoded()));
                        // put("ip", messageKeyValues.get("ip"));
                        put("nonce", nonceServer);
                    }});

                    // System.out.println("[server] Sending public key to client " + messageKeyValues.get("ip"));
                    System.out.println("[server] public key in bytes: " + Arrays.toString(serverRepository.getPublicKey().getEncoded()));

                    out.writeUTF(publicKeyMessage);

                    MyLogger.log("[server] public key sent to client");
                }
            } else if (messageKeyValues.get("message").equals("MAC")) {
                macKey = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("macKey")),
                        serverRepository.getPrivateKey());

                MAC = Authentication.generateMAC(messageKeyValues.get("secretMessage").getBytes(),
                        macKey);
                /*
                var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                if (user == null) {
                    // user must send the hello message first
                    System.out.println("[server] Send HELLO message first: User not found");
                    return;
                }

                user.setMAC(MAC);

                 */


                String m = Message.formatMessage("MAC_RECEIVED", new HashMap<>() {{
                    // put("ip", messageKeyValues.get("ip"));
                    put("mac", Confidentiality.encodeByteKeyToStringBase64(MAC));
                }});

                out.writeUTF(m);

                MyLogger.log("[server] MAC received");


            } else if (messageKeyValues.get("message").equals("REGISTER")) {
                // check MAC to see integrity and authentication
                if (MAC != null && Arrays.equals(MAC, Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("MAC verified");

                    // get all users from db and check if the username is already taken

                    for (var user : serverRepository.getUsers()) {

                        if (user.getUsername() == null) {
                            continue;
                        }

                        if (user.getUsername().equals(messageKeyValues.get("username"))) {
                            System.out.println("[server] Username already taken");
                            String m = Message.formatMessage("USERNAME_TAKEN", new HashMap<>() {{
                                // put("ip", messageKeyValues.get("ip"));
                            }});

                            out.writeUTF(m);

                            MyLogger.log("[server] " + m);

                            return;
                        }
                    }

                    var retrievedIV = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("iv")),
                            serverRepository.getPrivateKey());
                    var retrievedAESKey = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("aesKey")),
                            serverRepository.getPrivateKey());
                    var retrievedSalt = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("salt")),
                            serverRepository.getPrivateKey());
                    SecretKey aesKey = new SecretKeySpec(retrievedAESKey, 0, retrievedAESKey.length, "AES");
                    var retrievedPassword = Confidentiality.decryptWithAES(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("password")),
                            aesKey, retrievedIV);

                    System.out.println("[server] Password received: " + Arrays.toString(retrievedPassword));

                    var hashedPassword = Authentication.hashPassword(Arrays.toString(retrievedPassword), retrievedSalt);





                    // var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                    var user = new UserDTO(messageKeyValues.get("username"), hashedPassword, retrievedSalt);

                    user.setPublicKey(Confidentiality.getPublicKeyFromByteArray(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("publicKey"))));


                    // sign client public key with client username and create a certificate
                    UserCertificateCredentials userCertificateCredentials =
                            new UserCertificateCredentials(messageKeyValues.get("username"), Confidentiality.getPublicKeyFromString(messageKeyValues.get("publicKey")));
                    byte[] sign = Authentication.sign(userCertificateCredentials.getCredentialBytes(), serverRepository.getPrivateKey());
                    Certificate certificate = new Certificate(userCertificateCredentials, sign);
                    createCertificate(userCertificateCredentials, sign);

                    user.setCertificate(certificate);

                    String certificateMsg = Message.formatMessage("CERTIFICATE", new HashMap<>() {
                        {
                            // put("ip", messageKeyValues.get("ip"));
                            put("certificateSign", Confidentiality.encodeByteKeyToStringBase64(sign));
                            put("username", userCertificateCredentials.getUsername());
                            put("publicKey", userCertificateCredentials.getPublicKey().toString());
                            put("signature", Confidentiality.encodeByteKeyToStringBase64(certificate.getSignature()));
                            put("password", Base64.getEncoder().encodeToString(hashedPassword));
                        }

                    });


                    out.writeUTF(certificateMsg);

                    MyLogger.log("[server] " + certificateMsg);

                    var _u = serverRepository.getUserWithUsername(messageKeyValues.get("username"));


                    System.out.println("[server] user registered info: " + _u.getUsername() + " " + Arrays.toString(_u.getPassword()) +
                            " certificate uname: " + _u.getCertificate().getCertificateCredentials().getUsername() + " salt: " + Arrays.toString(_u.getPasswordSalt()));
                        /*
                        var _u = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                        System.out.println("[server] user registered info: " + _u.getUsername() + " " + Arrays.toString(_u.getPassword()) +
                                " certificate uname: " + _u.getCertificate().getCertificateCredentials().getUsername());

                         */

                } else {
                    System.out.println("MAC not verified");
                }


            } else if (messageKeyValues.get("message").equals("LOGIN")) {
                // check MAC to see integrity and authentication
                if (Arrays.equals(MAC, Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("[server] LOGIN MAC verified");

                    var retrievedIV = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("iv")),
                            serverRepository.getPrivateKey());
                    var retrievedAESKey = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("aesKey")),
                            serverRepository.getPrivateKey());
                    var salt = serverRepository.getUserWithUsername(messageKeyValues.get("username")).getPasswordSalt();
                    SecretKey aesKey = new SecretKeySpec(retrievedAESKey, 0, retrievedAESKey.length, "AES");
                    var retrievedPassword = Confidentiality.decryptWithAES(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("password")),
                            aesKey, retrievedIV);

                    System.out.println("[server] LOGIN Password received: " + Arrays.toString(retrievedPassword));

                    var hashedPassword = Authentication.hashPassword(Arrays.toString(retrievedPassword), salt);

                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));

                    if (Arrays.equals(user.getPassword(), hashedPassword)) {
                        System.out.println("[server] Passwords match");

                        Session session = new Session(messageKeyValues.get("username"));

                        user.setSession(session);

                        //TODO: encrypt session id with user public key
                        String loginMsg = Message.formatMessage("AUTHENTICATED", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("sessionID", session.getSessionID());
                        }});


                        out.writeUTF(loginMsg);

                        MyLogger.log("[server] " + loginMsg);

                    } else {
                        System.out.println("[server] Passwords do not match");

                        String loginMsg = Message.formatMessage("LOGIN", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                            put("loginStatus", "FAILED");
                        }});


                        out.writeUTF(loginMsg);

                        MyLogger.log("[server] " + loginMsg);
                    }

                } else {
                    System.out.println("MAC not verified");
                }

            } else if (messageKeyValues.get("message").equals("ACCESSIBILITY")) {
                if (Arrays.equals(MAC, Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("[server] POST IMAGE MAC verified");

                    var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                            serverRepository.getPrivateKey());
                    System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));
                    var session = user.getSession();

                    if (user.getSession() == null) {
                        System.out.println("[server] username: " + messageKeyValues.get("username") + " not authenticated");

                        String m = Message.formatMessage("SESSION_NOT_FOUND", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);

                    }

                    if (session.isTimedOut()) {
                        System.out.println("[server] session for username: " + messageKeyValues.get("username") + " is timed out");
                        user.setSession(null);

                        String m = Message.formatMessage("SESSION_TIME_OUT", new HashMap<>() {{
                            //put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);
                    }

                    session.updateLastAccess();

                    if (messageKeyValues.get("accessList").equals("[ALL]")) {

                        String m = Message.formatMessage("SESSION_VALID", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                            put("all", Confidentiality.encodeByteKeyToStringBase64(serverRepository.getPublicKey().getEncoded()));

                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);

                    } else {
                        var list = Message.parseArrayString(messageKeyValues.get("accessList"));
                        var pubKeysResponse = new HashMap<String, String>();
                        for (var acc : list) {
                            var userDTO = serverRepository.getUserWithUsername(acc);
                            if (userDTO != null) {
                                pubKeysResponse.put(acc,
                                        Confidentiality.encodeByteKeyToStringBase64(userDTO.getCertificate().getCertificateCredentials().getPublicKey().getEncoded()));
                            } else {
                                System.out.println("[server] user: " + acc + "in the access list not found");

                            }
                        }

                        pubKeysResponse.put("username", messageKeyValues.get("username"));

                        String m = Message.formatMessage("SESSION_VALID", pubKeysResponse);

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);


                    }


                } else {
                    System.out.println("MAC not verified");
                }
            } else if (messageKeyValues.get("message").equals("POST_IMAGE")) {

                if (Arrays.equals(MAC, Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("MAC verified");


                    for (var msg : messageKeyValues.entrySet()) {
                        System.out.println("[server] key: " + msg.getKey() + " value: " + msg.getValue());
                    }

                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));


                    var imageDownloadData = new ImageDownloadData(
                            messageKeyValues.get("imageName"),
                            Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("imageBytes")),
                            Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("digitalSignature")),
                            user.getPublicKey().getEncoded(),
                            Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("iv"))
                    );

                    var imageMetaData = new ImageMetaData();

                    for (var msg : messageKeyValues.entrySet()) {
                        if (!msg.getKey().equals("message") && !msg.getKey().equals("imageName") &&
                                !msg.getKey().equals("imageBytes") && !msg.getKey().equals("digitalSignature") &&
                                !msg.getKey().equals("iv") && !msg.getKey().equals("sessionID") && !msg.getKey().equals("mac")
                                && !msg.getKey().equals("username")) {

                            if (msg.getKey().equals("all")) {
                                var decryptedAESKey = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(msg.getValue()),
                                        serverRepository.getPrivateKey());
                                imageDownloadData.addEncryptedAESKey(msg.getKey(), decryptedAESKey);
                                imageMetaData.addToAccessList(msg.getKey());
                            } else {
                                imageDownloadData.addEncryptedAESKey(msg.getKey(),
                                        Confidentiality.decodeStringKeyToByteBase64(msg.getValue()));
                                imageMetaData.addToAccessList(msg.getKey());
                            }


                        }
                    }

                    System.out.println("******************");
                    System.out.println("[server]access list image data save val");

                    imageMetaData.setOwnerName(user.getUsername());

                    for (var msg : imageDownloadData.getAesKeys().entrySet()) {
                        System.out.println("[server] key: " + msg.getKey() + " value: " + Arrays.toString(msg.getValue()));
                    }

                    System.out.println("******************");

                    serverRepository.saveImage(imageMetaData, imageDownloadData);

                    // send notification to all online users

                    if (messageKeyValues.get("all") != null) {
                        for (var handler : Server.getClientHandlers()) {
                            new Thread(() -> {
                                handler.sendNotification(messageKeyValues);
                            }).start();
                        }
                    }
                } else {
                    System.out.println("MAC not verified");
                }


            } else if (messageKeyValues.get("message").equals("SESSION_NOTIFICATION")) {

                if (Arrays.equals(MAC, Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("MAC verified");

                    var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                            serverRepository.getPrivateKey());
                    System.out.println("[server] post image arrived NOTIFICATION session id: " + Arrays.toString(sessionID));

                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));
                    var session = user.getSession();

                    if (user.getSession() == null) {
                        System.out.println("[server] username: " + messageKeyValues.get("username") + " not authenticated");

                        String m = Message.formatMessage("SESSION_NOT_FOUND_NOTIFICATION", new HashMap<>() {{
                            //put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);
                    }

                    if (session.isTimedOut()) {
                        System.out.println("[server] session for username: " + messageKeyValues.get("username") + " is timed out");
                        user.setSession(null);

                        String m = Message.formatMessage("SESSION_TIME_OUT_NOTIFICATION", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);
                    }

                    session.updateLastAccess();

                    sendNotificationLock.lock();
                    try {
                        sendNotificationContinue = true;
                        sendNotificationCondition.signal();
                    } finally {
                        sendNotificationLock.unlock();
                    }
                } else {
                    System.out.println("MAC not verified");
                }


            } else if (messageKeyValues.get("message").equals("DOWNLOAD")) {
                System.out.println("[server] DOWNLOAD message arrived");

                    var image = serverRepository.getImageByName(messageKeyValues.get("imageName"));
                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));

                    if (user == null) {
                        System.out.println("[server] user not found");

                        String m = Message.formatMessage("USER_NOT_FOUND", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);

                    }

                    if (image == null) {
                        System.out.println("[server] Image not found");

                        String m = Message.formatMessage("IMAGE_NOT_FOUND", new HashMap<>() {{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }});

                        out.writeUTF(m);

                        MyLogger.log("[server] " + m);

                    } else {
                            System.out.println("[server] Image found");

                            var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                                    serverRepository.getPrivateKey());
                            System.out.println("[server] post image arrived DOWNLOAD session id: " + Arrays.toString(sessionID));

                            var session = user.getSession();

                            if (session == null) {
                                System.out.println("[server] username: " + messageKeyValues.get("username") + " not authenticated");

                                String m = Message.formatMessage("SESSION_NOT_FOUND_DOWNLOAD", new HashMap<>() {{
                                    // put("ip", messageKeyValues.get("ip"));
                                    put("username", messageKeyValues.get("username"));
                                }});

                                out.writeUTF(m);

                                MyLogger.log("[server] " + m);

                                return;
                            }

                            if (session.isTimedOut()) {
                                System.out.println("[server] session for username: " + messageKeyValues.get("username") + " is timed out");
                                user.setSession(null);

                                String m  =Message.formatMessage("SESSION_TIME_OUT_DOWNLOAD", new HashMap<>() {{
                                    // put("ip", messageKeyValues.get("ip"));
                                    put("username", messageKeyValues.get("username"));
                                }});

                                out.writeUTF(m);

                                MyLogger.log("[server] " + m);
                            }

                            session.updateLastAccess();



                            // get the key value of the image map
                            for (var img : image.entrySet()) {

                                var ownerPublicKey = serverRepository.getUserWithUsername(img.getKey().getOwnerName()).getPublicKey();

                               if (img.getKey().getAccessList().contains("all")) {

                                   var aesKey = img.getValue().getAesKeys().get("all");
                                   var encryptedAESKey = Confidentiality.encryptWithPublicKey(aesKey, serverRepository.getUserWithUsername(messageKeyValues.get("username")).getPublicKey());
                                    var downloadMessage = Message.formatMessage("DOWNLOAD_IMAGE", new HashMap<>() {{
                                        // put("ip", messageKeyValues.get("ip"));
                                        put("username", messageKeyValues.get("username"));
                                        put("imageName", img.getValue().getImageName());
                                        put("imageBytes", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getEncryptedImage()));
                                        put("digitalSignature", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getDigitalSignature()));
                                        put("iv", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getIv()));
                                        put("ownerPublicKey", Confidentiality.encodeByteKeyToStringBase64(ownerPublicKey.getEncoded()));
                                        put("encryptedAESKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAESKey));
                                        put("access", "All");
                                    }});

                                    out.writeUTF(downloadMessage);

                                    MyLogger.log("[server] " + downloadMessage);

                               } else if (img.getKey().getAccessList().contains(user.getUsername())) {

                                    var encryptedAESKey = img.getValue().getAesKeys().get(user.getUsername());
                                    var downloadMessage = Message.formatMessage("DOWNLOAD_IMAGE", new HashMap<>() {{
                                        // put("ip", messageKeyValues.get("ip"));
                                        put("username", messageKeyValues.get("username"));
                                        put("imageName", img.getValue().getImageName());
                                        put("imageBytes", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getEncryptedImage()));
                                        put("digitalSignature", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getDigitalSignature()));
                                        put("iv", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getIv()));
                                        put("ownerPublicKey", Confidentiality.encodeByteKeyToStringBase64(ownerPublicKey.getEncoded()));
                                        put("encryptedAESKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAESKey));
                                        put("access", user.getUsername());
                                    }});

                                    out.writeUTF(downloadMessage);

                                    MyLogger.log("[server] " + downloadMessage);
                                } else {
                                    System.out.println("[server] user: " + user.getUsername() + " not in the access list of the image: " + img.getValue().getImageName());
                                    String m = Message.formatMessage("ACCESS_DENIED", new HashMap<>() {{
                                        // put("ip", messageKeyValues.get("ip"));
                                        put("username", messageKeyValues.get("username"));
                                    }});

                                    out.writeUTF(m);

                                    MyLogger.log("[server] " + m);
                                }


                            }



                        }


            } else {
                System.out.println("Invalid message");

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void sendNotification(Map<String, String> messageKeyValues) {
        try {
         DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            var requestSessionMessage = Message.formatMessage("REQUEST_SESSION_NOTIFICATION", new HashMap<>(){{
                put("desc", "i need your session to send you notification");
            }});

            out.writeUTF(requestSessionMessage);

            MyLogger.log("[server] " + requestSessionMessage);

            sendNotificationLock.lock();
            try {
                while (!sendNotificationContinue) {
                    sendNotificationCondition.await();
                }
                sendNotificationContinue = false;
            } finally {
                sendNotificationLock.unlock();

            }


            var notificationMessage = Message.formatMessage("NEW_IMAGE", new HashMap<>(){{
                // put("ip", messageKeyValues.get("ip"));
                put("username", messageKeyValues.get("username"));
                put("imageName", messageKeyValues.get("imageName"));
                put("owner", messageKeyValues.get("username"));
            }});

            out.writeUTF(notificationMessage);

            MyLogger.log("[server] " + notificationMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {
        listen();
    }
}
