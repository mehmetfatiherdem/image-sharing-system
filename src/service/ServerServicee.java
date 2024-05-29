package service;

import java.util.Map;

public interface ServerServicee {
    void listen();
    void handleClientMessage(Map<String, String> messageKeyValues);
    void sendNotification();
}
