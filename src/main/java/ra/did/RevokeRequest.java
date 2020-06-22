package ra.did;

import ra.common.DID;
import ra.common.ServiceMessage;

/**
 * Revoke Identity.
 *
 * @author objectorange
 */
public class RevokeRequest extends ServiceMessage {

    public static final int DID_REQUIRED = 1;

    public DID did;
}
