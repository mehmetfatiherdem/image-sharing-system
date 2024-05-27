package service;

import dto.UserDTO;
import helper.format.Message;
import helper.image.ImageDownloadData;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import model.Certificate;
import model.Session;
import repository.ServerRepository;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class ServerServiceImpl implements ServerService, Runnable {
    private final ServerRepository serverRepository;
    private final Socket socket;

    public ServerServiceImpl(ServerRepository serverRepository, Socket socket) {
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
    public void sendImagePostNotification(ArrayList<UserDTO> onlineUsers, String imageName, String ownerUsername) {
        // implement this method
    }

    @Override
    public void sendImage(ImageDownloadData imageDownloadData) {

        try {
            /*
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(imageDownloadData.getMessageString());

             */
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void handleRequests(Socket socket) {
        try {

            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());


            while (true) {

                String message = in.readUTF();

                var messageKeyValues = Message.getKeyValuePairs(message);


                if (messageKeyValues.get("message").equals("HELLO")) {

                    
                        try {

                            if (serverRepository.getNoncesUsed(messageKeyValues.get("ip")) != null &&
                                    serverRepository.getNoncesUsed(messageKeyValues.get("ip")).contains(messageKeyValues.get("nonce"))) {
                                System.out.println("[server] Nonce already used REPLAY ATTACK ALERT!!!: " + messageKeyValues.get("nonce"));

                            } else {

                                String nonceServer = Authentication.generateNonce();

                                if(serverRepository.getUserWithIP(messageKeyValues.get("ip")) != null){
                                    serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));

                                } else {
                                    serverRepository.addUser(new UserDTO(messageKeyValues.get("ip")));
                                    serverRepository.addNonceUsed(messageKeyValues.get("ip"), messageKeyValues.get("nonce"));
                                }

                                System.out.println("[server] Nonce added to list: " + messageKeyValues.get("nonce"));
                                System.out.println("[server] ip: " + messageKeyValues.get("ip"));


                                String publicKeyMessage = Message.formatMessage("PUBLICKEY", new String[]{"publicKey", "ip", "nonce"},
                                        new String[]{Confidentiality.encodeByteKeyToStringBase64(serverRepository.getPublicKey().getEncoded()), messageKeyValues.get("ip"), nonceServer});

                                out.writeUTF(publicKeyMessage);

                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                }
                           else if (messageKeyValues.get("message").equals("MAC")) {
                                var mac = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("macKey")),
                                        serverRepository.getPrivateKey());

                                byte[] MAC = Authentication.generateMAC(messageKeyValues.get("secretMessage").getBytes(),
                                        mac);

                                var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));

                                if(user == null){
                                    // user must send the hello message first
                                    System.out.println("[server] Send HELLO message first: User not found");
                                    return;
                                }

                                user.setMAC(MAC);

                                System.out.println("MAC generated by server: " + Arrays.toString(MAC));



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
                        user.setOnline(false);


                        // sign client public key with client username and create a certificate
                        UserCertificateCredentials userCertificateCredentials =
                                new UserCertificateCredentials(messageKeyValues.get("username"), Confidentiality.getPublicKeyFromString(messageKeyValues.get("publicKey")));
                        byte[] sign = Authentication.sign(userCertificateCredentials.getCredentialBytes(), serverRepository.getPrivateKey());
                        Certificate certificate = new Certificate(userCertificateCredentials, sign);
                        createCertificate(userCertificateCredentials, sign, messageKeyValues.get("ip"));

                        user.setCertificate(certificate);

                        String certificateMsg = Message.formatMessage("CERTIFICATE", new String[]{"ip", "certificateSign", "username", "publicKey", "signature", "password"},
                                new String[]{messageKeyValues.get("ip"), Confidentiality.encodeByteKeyToStringBase64(sign), userCertificateCredentials.getUsername(),
                                        userCertificateCredentials.getPublicKey().toString(),
                                        Confidentiality.encodeByteKeyToStringBase64(certificate.getSignature()),
                                        Base64.getEncoder().encodeToString(hashedPassword)});

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

                            String loginMsg = Message.formatMessage("AUTHENTICATED", new String[]{"ip", "sessionID"},
                                    new String[]{messageKeyValues.get("ip"), session.getSessionID()});

                            out.writeUTF(loginMsg);

                        } else {
                            System.out.println("[server] Passwords do not match");

                            String loginMsg = Message.formatMessage("LOGIN", new String[]{"ip", "message"},
                                    new String[]{messageKeyValues.get("ip"), "LOGIN FAILED"});

                            out.writeUTF(loginMsg);
                        }

                    } else {
                        System.out.println("MAC not verified");
                    }

                } else if (messageKeyValues.get("message").equals("SESSIONID")) {
                    if (Arrays.equals(serverRepository.getUserWithIP(messageKeyValues.get("ip")).getMAC(), Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("mac")))) {
                        System.out.println("[server] POST IMAGE MAC verified");

                        var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                                serverRepository.getPrivateKey());
                        System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                        var user = serverRepository.getUserWithIP(messageKeyValues.get("ip"));
                        var session = user.getSession();

                        if(user.getSession() == null) {
                            System.out.println("[server] userIP: " + messageKeyValues.get("ip") + " not authenticated");
                            out.writeUTF(Message.formatMessage("SESSION_NOT_FOUND",  new String[]{"ip"},
                                    new String[]{messageKeyValues.get("ip")}));
                            continue;
                        }

                        if(session.isTimedOut()) {
                            System.out.println("[server] session for userIP: " + messageKeyValues.get("ip") + " is timed out");
                            user.setSession(null);
                            out.writeUTF(Message.formatMessage("SESSION_TIME_OUT",  new String[]{"ip"},
                                    new String[]{messageKeyValues.get("ip")}));
                            continue;
                        }

                        session.updateLastAccess();

                        out.writeUTF(Message.formatMessage("SESSION_VALID",  new String[]{"ip"},
                                new String[]{messageKeyValues.get("ip")}));


                    } else {
                        System.out.println("MAC not verified");
                    }
                }
                   else {
                    System.out.println("Invalid message");

                }


            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        try {
            handleRequests(socket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
