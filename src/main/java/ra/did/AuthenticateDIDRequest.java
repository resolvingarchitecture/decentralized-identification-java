package ra.did;

import ra.common.identity.DID;
import ra.common.service.ServiceMessage;

public class AuthenticateDIDRequest extends ServiceMessage {
    public static final int DID_REQUIRED = 1;
    public static final int DID_FINGERPRINT_REQUIRED = 2;
    public static final int DID_PASSPHRASE_REQUIRED = 3;
    public static final int DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN = 4;
    public static final int DID_USERNAME_UNKNOWN = 5;

    public DID did;
    public Boolean autogenerate = true;
    public Boolean isNode = false;

}
