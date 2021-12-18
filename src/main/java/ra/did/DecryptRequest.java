package ra.did;

import ra.common.content.Content;

public class DecryptRequest extends DIDRequest {

    public static int CONTENT_TO_DECRYPT_REQUIRED = 2;
    public static int PUBLIC_KEY_ALIAS_REQUIRED = 3;
    public static int PUBLIC_KEY_NOT_FOUND = 4;
    public static int LOCATION_REQUIRED = 5;
    public static int LOCATION_INACCESSIBLE = 6;

    public String location;
    public String keyRingUsername;
    public String keyRingPassphrase;
    public String alias;
    public Content content;
    public Boolean passphraseOnly = false;
}
