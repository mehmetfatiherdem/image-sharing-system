package service;

import helper.format.Message;
import repository.ServerRepository;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Map;

public class ServerServiceeImpl implements ServerServicee, Runnable{

    private ServerRepository serverRepository;
    private Socket socket;

    public ServerServiceeImpl(ServerRepository serverRepository, Socket socket) {
        this.serverRepository = serverRepository;
        this.socket = socket;
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

    }

    @Override
    public void sendNotification() {

    }

    @Override
    public void run() {
        listen();
    }
}
