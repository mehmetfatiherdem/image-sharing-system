package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageDownloadData;
import helper.image.ImageMetaData;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import model.Certificate;
import model.Server;
import model.Session;
import repository.ServerRepository;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class ServerServiceeImpl implements ServerServicee, Runnable{

    private ServerRepository serverRepository;
    private Socket socket;
    private final Lock sendNotificationLock = new ReentrantLock();
    private final Condition sendNotificationCondition = sendNotificationLock.newCondition();
    private boolean sendNotificationContinue = false;

    public ServerServiceeImpl(ServerRepository serverRepository, Socket socket) {
        this.serverRepository = serverRepository;
        this.socket = socket;
    }

    @Override
    public void createCertificate(UserCertificateCredentials userCertificateCredentials, byte[] sign, String ip) {
        try{
            //byte[] certificate = Authentication.sign(userCertificateCredentials.getCredentialBytes(), privateKey);
            serverRepository.addCertificate(new Certificate(userCertificateCredentials, sign), ip);
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
                if (serverRepository.getNoncesUsed(messageKeyValues.get("ip")) != null &&
                        serverRepository.getNoncesUsed(messageKeyValues.get("ip")).contains(messageKeyValues.get("nonce"))) {
                    System.out.println("[server] Nonce already used REPLAY ATTACK ALERT!!!: " + messageKeyValues.get("nonce"));

                } else {
                    String nonceServer = Authentication.generateNonce();

                    if (serverRepository.getUserWithIP(messageKeyValues.get("ip")) != null) {
                        serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));

                    } else {
                        for (var msg : messageKeyValues.entrySet()) {
                            System.out.println("[server] key: " + msg.getKey() + " value: " + msg.getValue());
                        }

                        serverRepository.addUser(new UserDTO(messageKeyValues.get("ip")));
                        serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));
                    }

                    System.out.println("[server] Nonce added to list: " + messageKeyValues.get("nonce"));
                    System.out.println("[server] ip: " + messageKeyValues.get("ip"));


                    String publicKeyMessage = Message.formatMessage("PUBLICKEY", new HashMap<>() {{
                        put("publicKey", Confidentiality.encodeByteKeyToStringBase64(serverRepository.getPublicKey().getEncoded()));
                        put("ip", messageKeyValues.get("ip"));
                        put("nonce", nonceServer);
                    }});

                    out.writeUTF(publicKeyMessage);
                }
            } else if (messageKeyValues.get("message").equals("MAC")) {
                var mac = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("macKey")),
                        serverRepository.getPrivateKey());

                byte[] MAC = Authentication.generateMAC(messageKeyValues.get("secretMessage").getBytes(),
                        mac);

                var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                if (user == null) {
                    // user must send the hello message first
                    System.out.println("[server] Send HELLO message first: User not found");
                    return;
                }

                user.setMAC(MAC);

                out.writeUTF(Message.formatMessage("MAC_RECEIVED", new HashMap<>() {{
                    put("ip", messageKeyValues.get("ip"));
                    put("mac", Confidentiality.encodeByteKeyToStringBase64(MAC));
                }}));


            } else if (messageKeyValues.get("message").equals("REGISTER")) {
                // check MAC to see integrity and authentication
                if (Arrays.equals(serverRepository.getUserWithIP(messageKeyValues.get("ip")).getMAC(), Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("MAC verified");

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

                    var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                    user.setPassword(hashedPassword);
                    user.setPasswordSalt(retrievedSalt);
                    user.setUsername(messageKeyValues.get("username"));
                    user.setPublicKey(Confidentiality.getPublicKeyFromByteArray(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("publicKey"))));
                    user.setOnline(false);


                    // sign client public key with client username and create a certificate
                    UserCertificateCredentials userCertificateCredentials =
                            new UserCertificateCredentials(messageKeyValues.get("username"), Confidentiality.getPublicKeyFromString(messageKeyValues.get("publicKey")));
                    byte[] sign = Authentication.sign(userCertificateCredentials.getCredentialBytes(), serverRepository.getPrivateKey());
                    Certificate certificate = new Certificate(userCertificateCredentials, sign);
                    createCertificate(userCertificateCredentials, sign, messageKeyValues.get("ip"));

                    user.setCertificate(certificate);

                    String certificateMsg = Message.formatMessage("CERTIFICATE", new HashMap<>() {
                        {
                            put("ip", messageKeyValues.get("ip"));
                            put("certificateSign", Confidentiality.encodeByteKeyToStringBase64(sign));
                            put("username", userCertificateCredentials.getUsername());
                            put("publicKey", userCertificateCredentials.getPublicKey().toString());
                            put("signature", Confidentiality.encodeByteKeyToStringBase64(certificate.getSignature()));
                            put("password", Base64.getEncoder().encodeToString(hashedPassword));
                        }

                    });


                    out.writeUTF(certificateMsg);

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
                if (Arrays.equals(serverRepository.getUserWithIP(messageKeyValues.get("ip")).getMAC(), Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
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

                    var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                    if (Arrays.equals(user.getPassword(), hashedPassword)) {
                        System.out.println("[server] Passwords match");

                        user.setOnline(true);

                        Session session = new Session(messageKeyValues.get("username"));

                        user.setSession(session);

                        //TODO: encrypt session id with user public key
                        String loginMsg = Message.formatMessage("AUTHENTICATED", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                            put("sessionID", session.getSessionID());
                        }});


                        out.writeUTF(loginMsg);

                    } else {
                        System.out.println("[server] Passwords do not match");

                        String loginMsg = Message.formatMessage("LOGIN", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                            put("loginStatus", "FAILED");
                        }});


                        out.writeUTF(loginMsg);
                    }

                } else {
                    System.out.println("MAC not verified");
                }

            } else if (messageKeyValues.get("message").equals("ACCESSIBILITY")) {
                if (Arrays.equals(serverRepository.getUserWithIP(messageKeyValues.get("ip")).getMAC(),
                        Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                    System.out.println("[server] POST IMAGE MAC verified");

                    var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                            serverRepository.getPrivateKey());
                    System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                    var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));
                    var session = user.getSession();

                    if (user.getSession() == null) {
                        System.out.println("[server] userIP: " + messageKeyValues.get("ip") + " not authenticated");
                        out.writeUTF(Message.formatMessage("SESSION_NOT_FOUND", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                        }}));

                    }

                    if (session.isTimedOut()) {
                        System.out.println("[server] session for userIP: " + messageKeyValues.get("ip") + " is timed out");
                        user.setSession(null);
                        out.writeUTF(Message.formatMessage("SESSION_TIME_OUT", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                        }}));
                    }

                    session.updateLastAccess();

                    if (messageKeyValues.get("accessList").equals("[ALL]")) {
                        out.writeUTF(Message.formatMessage("SESSION_VALID", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                            put("all", Confidentiality.encodeByteKeyToStringBase64(serverRepository.getPublicKey().getEncoded()));

                        }}));


                    } else {
                        var list = Message.parseArrayString(messageKeyValues.get("accessList"));
                        var pubKeysResponse = new HashMap<String, String>();
                        for (var acc : list) {
                            var userDTO = serverRepository.getUserWithUsername(acc);
                            if (userDTO != null) {
                                pubKeysResponse.put(acc,
                                        Confidentiality.encodeByteKeyToStringBase64(Authentication.sign(userDTO.getCertificate().getCertificateCredentials().getPublicKey().getEncoded(), serverRepository.getPrivateKey())));
                            } else {
                                System.out.println("[server] user: " + acc + "in the access list not found");

                            }
                        }

                        pubKeysResponse.put("ip", messageKeyValues.get("ip"));

                        out.writeUTF(Message.formatMessage("SESSION_VALID", pubKeysResponse));


                    }


                } else {
                    System.out.println("MAC not verified");
                }
            } else if (messageKeyValues.get("message").equals("POST_IMAGE")) {

                for (var msg : messageKeyValues.entrySet()) {
                    System.out.println("[server] key: " + msg.getKey() + " value: " + msg.getValue());
                }

                var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));


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
                            && !msg.getKey().equals("ip")) {
                        imageDownloadData.addEncryptedAESKey(msg.getKey(),
                                Confidentiality.decodeStringKeyToByteBase64(msg.getValue()));
                        imageMetaData.addToAccessList(msg.getKey());
                    }
                }

                System.out.println("******************");
                System.out.println("[server]access list image data save val");

                imageMetaData.setOwnerName(user.getUsername());

                for (var msg : imageDownloadData.getEncryptedAESKeys().entrySet()) {
                    System.out.println("[server] key: " + msg.getKey() + " value: " + Arrays.toString(msg.getValue()));
                }

                System.out.println("******************");

                serverRepository.saveImage(imageMetaData, imageDownloadData);

                // send notification to all online users

                for (var handler : Server.getClientHandlers()) {
                    new Thread(() -> {
                        handler.sendNotification(messageKeyValues);
                    }).start();
                }

            } else if (messageKeyValues.get("message").equals("SESSION_NOTIFICATION")) {

                var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                        serverRepository.getPrivateKey());
                System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));
                var session = user.getSession();

                if (user.getSession() == null) {
                    System.out.println("[server] userIP: " + messageKeyValues.get("ip") + " not authenticated");
                    out.writeUTF(Message.formatMessage("SESSION_NOT_FOUND_NOTIFICATION", new HashMap<>() {{
                        put("ip", messageKeyValues.get("ip"));
                    }}));
                }

                if (session.isTimedOut()) {
                    System.out.println("[server] session for userIP: " + messageKeyValues.get("ip") + " is timed out");
                    user.setSession(null);
                    out.writeUTF(Message.formatMessage("SESSION_TIME_OUT_NOTIFICATION", new HashMap<>() {{
                        put("ip", messageKeyValues.get("ip"));
                    }}));
                }

                session.updateLastAccess();

                sendNotificationLock.lock();
                try {
                    sendNotificationContinue = true;
                    sendNotificationCondition.signal();
                } finally {
                    sendNotificationLock.unlock();
                }


            } else if (messageKeyValues.get("message").equals("DOWNLOAD")) {
                System.out.println("[server] DOWNLOAD message arrived");

                    var image = serverRepository.getImageByName(messageKeyValues.get("imageName"));
                    var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                    if (user == null) {
                        System.out.println("[server] user not found");
                        out.writeUTF(Message.formatMessage("USER_NOT_FOUND", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                        }}));

                    }

                    if (image == null) {
                        System.out.println("[server] Image not found");
                        out.writeUTF(Message.formatMessage("IMAGE_NOT_FOUND", new HashMap<>() {{
                            put("ip", messageKeyValues.get("ip"));
                        }}));
                    } else {
                            System.out.println("[server] Image found");

                            var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                                    serverRepository.getPrivateKey());
                            System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                            var session = user.getSession();

                            if (session == null) {
                                System.out.println("[server] userIP: " + messageKeyValues.get("ip") + " not authenticated");
                                out.writeUTF(Message.formatMessage("SESSION_NOT_FOUND_DOWNLOAD", new HashMap<>() {{
                                    put("ip", messageKeyValues.get("ip"));
                                }}));
                            }

                            if (session.isTimedOut()) {
                                System.out.println("[server] session for userIP: " + messageKeyValues.get("ip") + " is timed out");
                                user.setSession(null);
                                out.writeUTF(Message.formatMessage("SESSION_TIME_OUT_DOWNLOAD", new HashMap<>() {{
                                    put("ip", messageKeyValues.get("ip"));
                                }}));
                            }

                            session.updateLastAccess();



                            // get the key value of the image map
                            for (var img : image.entrySet()) {

                                var ownerPublicKey = serverRepository.getUserWithUsername(img.getKey().getOwnerName()).getPublicKey();

                               if (img.getKey().getAccessList().contains("all")) {

                                   var encryptedAESKey = img.getValue().getEncryptedAESKeys().get("all");
                                    var downloadMessage = Message.formatMessage("DOWNLOAD_IMAGE", new HashMap<>() {{
                                        put("ip", messageKeyValues.get("ip"));
                                        put("imageName", img.getValue().getImageName());
                                        put("imageBytes", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getEncryptedImage()));
                                        put("digitalSignature", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getDigitalSignature()));
                                        put("iv", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getIv()));
                                        put("ownerPublicKey", Confidentiality.encodeByteKeyToStringBase64(ownerPublicKey.getEncoded()));
                                        put("encryptedAESKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAESKey));
                                        put("access", "All");
                                    }});

                                    out.writeUTF(downloadMessage);

                               } else if (img.getKey().getAccessList().contains(user.getUsername())) {

                                    var encryptedAESKey = img.getValue().getEncryptedAESKeys().get(user.getUsername());
                                    var downloadMessage = Message.formatMessage("DOWNLOAD_IMAGE", new HashMap<>() {{
                                        put("ip", messageKeyValues.get("ip"));
                                        put("imageName", img.getValue().getImageName());
                                        put("imageBytes", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getEncryptedImage()));
                                        put("digitalSignature", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getDigitalSignature()));
                                        put("iv", Confidentiality.encodeByteKeyToStringBase64(img.getValue().getIv()));
                                        put("ownerPublicKey", Confidentiality.encodeByteKeyToStringBase64(ownerPublicKey.getEncoded()));
                                        put("encryptedAESKey", Confidentiality.encodeByteKeyToStringBase64(encryptedAESKey));
                                        put("access", user.getUsername());
                                    }});

                                    out.writeUTF(downloadMessage);
                                } else {
                                    System.out.println("[server] user: " + user.getUsername() + " not in the access list of the image: " + img.getValue().getImageName());
                                    out.writeUTF(Message.formatMessage("ACCESS_DENIED", new HashMap<>() {{
                                        put("ip", messageKeyValues.get("ip"));
                                    }}));
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
                put("ip", messageKeyValues.get("ip"));
                put("imageName", messageKeyValues.get("imageName"));
                put("owner", serverRepository.getUserWithIP(messageKeyValues.get("ip")).getUsername());
            }});

            out.writeUTF(notificationMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {
        listen();
    }
}
