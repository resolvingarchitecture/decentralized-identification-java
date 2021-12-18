package ra.did;

import ra.common.identity.DID;
import ra.common.service.ServiceMessage;

public class AuthenticateDIDRequest extends ServiceMessage {
    public static final int USERNAME_REQUIRED = 1;
    public static final int PASSPHRASE_REQUIRED = 2;
    public static final int USERNAME_UNKNOWN = 3;
    public static final int PASSPHRASE_WRONG = 4;

    public String username;
    public String passphrase;
    public DID.Type type;
}
