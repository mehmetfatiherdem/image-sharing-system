package service;

import java.io.DataOutputStream;
import java.util.List;
import java.util.Map;

public interface UserService {
    void listenServer();
    void handleServerMessage(Map<String, String> messageKeyValues);
    void sendHelloMessage(DataOutputStream out);
    void sendMacKey(DataOutputStream out);
    void login(String username, String password);
    void register(String username, String password);
    void postImage(String imageName, String imagePath, List<String> accessList);
    void downloadImage(String imageName);
    void extractImage(Map<String, String> messageKeyValues);
}
