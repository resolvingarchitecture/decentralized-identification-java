package ra.did;

import ra.common.Hash;
import ra.common.ServiceMessage;

public class VerifyHashRequest extends ServiceMessage {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;

    // Request
    public String content;
    public Hash hashToVerify;
    public boolean isShort = false; // full is default
    // Result
    public boolean isAMatch;
}
