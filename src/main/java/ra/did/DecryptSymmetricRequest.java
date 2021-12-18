package ra.did;

import ra.common.content.Content;

public class DecryptSymmetricRequest extends DIDRequest {
    public static int ENCRYPTED_CONTENT_REQUIRED = 2;
    public static int PASSPHRASE_REQUIRED = 3;
    public static int IV_REQUIRED = 4;
    public static int BAD_PASSPHRASE = 5;
    public Content content;
}
