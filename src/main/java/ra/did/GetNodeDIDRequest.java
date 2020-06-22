package ra.did;

import ra.common.DID;
import ra.common.ServiceMessage;

public class GetNodeDIDRequest extends ServiceMessage {
    public static final int DID_REQUIRED = 1;
    public static final int DID_FINGERPRINT_REQUIRED = 2;
    public static final int DID_PASSPHRASE_REQUIRED = 3;
    public static final int DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN = 4;

    public DID did;
}
