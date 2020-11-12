package ra.did;

import ra.common.crypto.Hash;
import ra.common.service.ServiceMessage;

public class VerifyHashRequest extends ServiceMessage {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;

    // Request
    public byte[] content;
    public Hash hashToVerify;
    public boolean isShort = false; // full is default
    // Result
    public boolean isAMatch;
}
