package ra.did;

import ra.common.content.Content;

public class EncryptSymmetricRequest extends DIDRequest {

    public static int CONTENT_TO_ENCRYPT_REQUIRED = 2;
    public static int PASSPHRASE_REQUIRED = 3;

    public Content content;
}
