package ra.did;

import ra.common.identity.DID;
import ra.common.service.ServiceMessage;

/**
 * Revoke Identity.
 *
 * @author objectorange
 */
public class RevokeRequest extends ServiceMessage {

    public static final int DID_REQUIRED = 1;

    public DID did;
}
