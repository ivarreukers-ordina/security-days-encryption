package encryption;

import java.security.Key;

public class PublicKey {

    private int id;
    private String owner;
    private String mail;
    private String pubkey;
    private String key;

    public Key getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Key publicKey) {
        this.publicKey = publicKey;
    }

    private Key publicKey;

    public PublicKey() {
    }

    public PublicKey(int id, String owner, String mail, String pubkey, String key) {
        this.id = id;
        this.owner = owner;
        this.mail = mail;
        this.pubkey = pubkey;
        this.key = key;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getMail() {
        return mail;
    }

    public void setMail(String mail) {
        this.mail = mail;
    }

    public String getPubkey() {
        return pubkey;
    }

    public void setPubkey(String pubkey) {
        this.pubkey = pubkey;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }
}
