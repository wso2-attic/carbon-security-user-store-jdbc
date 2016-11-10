package org.wso2.carbon.security.userstore.jdbc.util;


import org.wso2.carbon.security.userstore.jdbc.connector.virtual.VirtualStoreConnector;


/**
 * ConnectorContextThreadLocal
 *
 */
public class ConnectorContextThreadLocal {

    private static ThreadLocal<VirtualStoreConnector> virtualStoreConnectorThreadLocal = new InheritableThreadLocal<>();

    public static VirtualStoreConnector getVirtualStoreConnector() {
        VirtualStoreConnector virtualStoreConnector = virtualStoreConnectorThreadLocal.get();
        if (virtualStoreConnector == null) {
            synchronized (virtualStoreConnectorThreadLocal) {
                if (virtualStoreConnector == null) {
                    virtualStoreConnector = new VirtualStoreConnector();
                    virtualStoreConnectorThreadLocal.set(virtualStoreConnector);
                }
            }
        }
        return virtualStoreConnector;
    }
}
