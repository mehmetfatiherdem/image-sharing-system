package helper.image;

import java.util.HashSet;
import java.util.Set;

public class ImageMetaData {
    private String ownerName;
    private Set<String> accessList = new HashSet<>();

    public ImageMetaData() {
    }

    public ImageMetaData(String ownerName, Set<String> accessList) {
        this.ownerName = ownerName;
        this.accessList = accessList;
    }

    public void addToAccessList(String username) {
        accessList.add(username);
    }

    public String getOwnerName() {
        return ownerName;
    }

    public Set<String> getAccessList() {
        return accessList;
    }

    public void setOwnerName(String ownerName) {
        this.ownerName = ownerName;
    }

    public void setAccessList(Set<String> accessList) {
        this.accessList = accessList;
    }
}
