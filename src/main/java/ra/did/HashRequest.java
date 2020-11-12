package ra.did;


import ra.common.crypto.Hash;
import ra.common.service.ServiceMessage;

public class HashRequest extends ServiceMessage {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;
    // Request
    public byte[] contentToHash;
    public boolean generateHash = true; // default
    public Hash.Algorithm hashAlgorithm = Hash.Algorithm.SHA256; // default
    public boolean generateFingerprint = true; // default
    public Hash.Algorithm fingerprintAlgorithm = Hash.Algorithm.SHA1; // default
    // Result
    public Hash hash;
    public Hash fingerprint;
}
