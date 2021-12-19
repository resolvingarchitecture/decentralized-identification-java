package ra.did;

import ra.common.service.ServiceMessage;

public abstract class DIDRequest extends ServiceMessage {

    public static int KEY_RING_IMPLEMENTATION_UNKNOWN = 1;

    public String keyRingImplementation = OpenPGPKeyRing.class.getName(); // default

    public Boolean successful = false;
}
