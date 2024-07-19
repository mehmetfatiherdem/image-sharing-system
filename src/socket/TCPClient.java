package socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class TCPClient implements Runnable{
    private final InetAddress serverAddress;
    private final int serverPort;
    private Socket socket;

    public TCPClient(InetAddress serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
    }

    @Override
    public void run() {
        try {
            socket = new Socket(serverAddress, serverPort);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Getters
    public Socket getSocket() {
        return socket;
    }
}
