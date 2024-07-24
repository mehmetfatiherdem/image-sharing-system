package service;

import helper.format.Message;
import helper.security.Confidentiality;
import repository.ServerRepository;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.HashMap;

public class NotificationServiceImpl implements NotificationService {

    private final ServerRepository serverRepository;
    private final Socket socket;

    public NotificationServiceImpl(ServerRepository serverRepository, Socket socket) {
        this.serverRepository = serverRepository;
        this.socket = socket;
    }

    @Override
    public void sendNotification(String message) {
        //TODO: request online users to send their session if it is valid send them notification

        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            var requestSessionMessage = Message.formatMessage("REQUEST_SESSION_NOTIFICATION", new HashMap<>(){{
                put("desc", "i need your session to send you notification");
            }});

            out.writeUTF(requestSessionMessage);

            while (true) {
                String response = in.readUTF();
                var messageKeyValues = Message.getKeyValuePairs(response);

                System.out.println("[server][notification]: client message: " + messageKeyValues);

                if (messageKeyValues.get("message").equals("SESSION_NOTIFICATION")) {
                    var sessionID = Confidentiality.decryptWithPrivateKey(Confidentiality.decodeStringKeyToByteBase64(messageKeyValues.get("sessionID")),
                            serverRepository.getPrivateKey());
                    System.out.println("[server] post image arrived session id: " + Arrays.toString(sessionID));

                    var user = serverRepository.getUserWithUsername(messageKeyValues.get("username"));
                    var session = user.getSession();

                    if(user.getSession() == null) {
                        System.out.println("[server] username: " + messageKeyValues.get("username") + " not authenticated");
                        out.writeUTF(Message.formatMessage("SESSION_NOT_FOUND_NOTIFICATION", new HashMap<>(){{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }}));
                        continue;
                    }

                    if(session.isTimedOut()) {
                        System.out.println("[server] session for username: " + messageKeyValues.get("username") + " is timed out");
                        user.setSession(null);
                        out.writeUTF(Message.formatMessage("SESSION_TIME_OUT_NOTIFICATION",  new HashMap<>(){{
                            // put("ip", messageKeyValues.get("ip"));
                            put("username", messageKeyValues.get("username"));
                        }}));
                        continue;
                    }

                    session.updateLastAccess();

                    var imageKeyValues = Message.getKeyValuePairs(message);

                    var notificationMessage = Message.formatMessage("NEW_IMAGE", new HashMap<>(){{
                        put("ip", messageKeyValues.get("ip"));
                        put("imageName", imageKeyValues.get("imageName"));
                        put("owner", serverRepository.getUserWithUsername(messageKeyValues.get("username")).getUsername());
                    }});

                    out.writeUTF(notificationMessage);
                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
