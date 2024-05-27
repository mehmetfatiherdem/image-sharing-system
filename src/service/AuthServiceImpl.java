package service;

import dto.UserDTO;
import helper.format.Message;
import helper.security.Authentication;
import helper.security.Confidentiality;
import helper.security.UserCertificateCredentials;
import model.Certificate;
import model.User;
import repository.UserRepository;
import userlocal.UserStorage;

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
            var userPersistent = userRepository.getPersistentUser(username);

            if (userPersistent.isEmpty()) {
                System.out.println("User not found");
                return;
            }

            //LoginDTO loginDTO = new LoginDTO(username, Base64.getDecoder().decode(password));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));

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

            String helloMsg = Message.formatMessage("HELLO", new String[]{"nonce", "ip"},
                    new String[]{nonceClient, user.getIP()});

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


            byte[] encryptedMacKey = Confidentiality.encryptWithPublicKey(macKey, serverPublicKey);
            String macKeyString = Message.formatMessage("MAC", new String[]{"secretMessage", "macKey", "ip"},
                    new String[]{"Secretmsg123!", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey), user.getIP()});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            //Thread.sleep(1000);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPublicKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);


            String loginMessagePayload = Message.formatMessage("LOGIN", new String[]{"ip", "username", "password", "iv", "aesKey", "mac"},
                    new String[]{user.getIP(), username, Confidentiality.encodeByteKeyToStringBase64(encryptedPassword), Confidentiality.encodeByteKeyToStringBase64(encryptedIv),
                    Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey), Confidentiality.encodeByteKeyToStringBase64(MAC)});


            out.writeUTF(loginMessagePayload);

            while (true) {
                String serverResponse2 = in.readUTF();
                var messageKeyValues2 = Message.getKeyValuePairs(serverResponse2);

                if (messageKeyValues2.get("ip").equals(user.getIP())) {
                    if(messageKeyValues2.get("message").equals("AUTHENTICATED")) {

                        System.out.println("[client] server response after login: " + messageKeyValues2.get("sessionID"));

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
            String macKeyString = Message.formatMessage("MAC", new String[]{"secretMessage", "macKey", "ip"},
                    new String[]{"Secretmsg123!", Confidentiality.encodeByteKeyToStringBase64(encryptedMacKey), user.getIP()});
            System.out.println("MAC generated by client: " + Arrays.toString(MAC));

            out.writeUTF(macKeyString);

            //Thread.sleep(1000);

            var aesKey = Confidentiality.generateAESKey(256);
            var iv = Confidentiality.generateIV(16);
            var encryptedPassword = Confidentiality.encryptWithAES(password.getBytes(), aesKey, iv);
            var encryptedIv = Confidentiality.encryptWithPublicKey(iv, serverPublicKey);
            var encryptedAesKey = Confidentiality.encryptWithPublicKey(aesKey.getEncoded(), serverPublicKey);
            var encryptedSalt = Confidentiality.encryptWithPublicKey(user.getPasswordSalt(), serverPublicKey);

            String message = Message.formatMessage("REGISTER", new String[]{"username", "password", "salt", "publicKey", "mac", "ip", "aesKey", "iv"},
                    new String[]{username, Confidentiality.encodeByteKeyToStringBase64(encryptedPassword),
                            Confidentiality.encodeByteKeyToStringBase64(encryptedSalt),
                                Base64.getEncoder().encodeToString(user.getKeyPair().getPublic().getEncoded()),
                                    Confidentiality.encodeByteKeyToStringBase64(MAC), user.getIP(),
                                        Confidentiality.encodeByteKeyToStringBase64(encryptedAesKey),
                                            Confidentiality.encodeByteKeyToStringBase64(encryptedIv)});



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
}
