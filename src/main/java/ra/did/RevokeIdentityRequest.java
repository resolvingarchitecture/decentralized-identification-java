package ra.did;

import ra.common.service.ServiceMessage;

public class RevokeIdentityRequest extends ServiceMessage {

    public static final int DID_REQUIRED = 1;

    public String username;
}
