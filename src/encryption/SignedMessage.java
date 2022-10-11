package encryption;

public class SignedMessage {
    private int id;
    private String sender;
    private String receiver;
    private String message;
    private String signature;

    public SignedMessage() {
    }

    public SignedMessage(int id, String sender, String receiver, String message, String signature) {
        this.id = id;
        this.sender = sender;
        this.receiver = receiver;
        this.message = message;
        this.signature = signature;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getReceiver() {
        return receiver;
    }

    public void setReceiver(String receiver) {
        this.receiver = receiver;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
