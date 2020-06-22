package ra.did;

import ra.common.Hash;
import ra.common.ServiceMessage;

public class HashRequest extends ServiceMessage {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;
    // Request
    public String contentToHash;
    public boolean generateHash = true; // default
    public boolean generateFingerprint = true; // default
    // Result
    public Hash hash;
    public Hash fingerprint;
}
