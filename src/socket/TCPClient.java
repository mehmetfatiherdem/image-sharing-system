package socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

public class TCPClient implements Runnable{
    private final String serverAddress;
    private final int serverPort;
    private Socket socket;

    public TCPClient(String serverAddress, int serverPort) {
        this.serverAddress = serverAddress;
        this.serverPort = serverPort;
    }

    @Override
    public void run() {
        while (true) {
            try {
                InetAddress address = InetAddress.getByName(serverAddress);
                socket = new Socket(address, serverPort);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Getters
    public String getServerAddress() {
        return serverAddress;
    }

    public int getServerPort() {
        return serverPort;
    }

    public Socket getSocket() {
        return socket;
    }
}
