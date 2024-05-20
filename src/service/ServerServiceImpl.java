package service;

import dto.UserDTO;
import helper.image.ImageDownloadData;
import helper.security.Authentication;
import helper.security.UserCertificateCredentials;
import repository.ServerRepository;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;

public class ServerServiceImpl implements ServerService {
    private final ServerRepository serverRepository;
    private final Socket socket;

    public ServerServiceImpl(ServerRepository serverRepository, Socket socket) {
        this.serverRepository = serverRepository;
        this.socket = socket;
    }
    @Override
    public void createCertificate(UserCertificateCredentials userCertificateCredentials, PrivateKey privateKey) {
        try{
            byte[] certificate = Authentication.sign(userCertificateCredentials.getCredentialBytes(), privateKey);
            serverRepository.addCertificate(certificate);
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
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.writeUTF(imageDownloadData.getMessageString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void handleRequests() {
        try {

            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            while (true) {

                String message = in.readUTF();
                String[] messageParts = message.split(" ");

                if (message.equals("ping")) {
                    out.writeUTF("pong");
                } else if (messageParts[0].equals("HELLO")) {
                    out.writeUTF( "PUBLICKEY" + " " + serverRepository.getPublicKey().toString());
                }
                else {
                    out.writeUTF("error");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
