package org.wso2.carbon.security.userstore.jdbc.connector.virtual;

import org.wso2.carbon.identity.mgt.exception.CredentialStoreException;
import org.wso2.carbon.security.userstore.jdbc.connector.JDBCCredentialStoreConnector;
import org.wso2.carbon.security.userstore.jdbc.util.ConnectorContextThreadLocal;

import javax.security.auth.callback.Callback;

/**
 * JDBCVirtualCredentialStoreConnector
 *
 */
public class JDBCVirtualCredentialStoreConnector extends JDBCCredentialStoreConnector {
    @Override
    public void addCredential(Callback[] callbacks) throws CredentialStoreException {
        VirtualStoreConnector virtualStoreConnector = ConnectorContextThreadLocal.getVirtualStoreConnector();
        virtualStoreConnector.addCredential(callbacks);
    }
}
