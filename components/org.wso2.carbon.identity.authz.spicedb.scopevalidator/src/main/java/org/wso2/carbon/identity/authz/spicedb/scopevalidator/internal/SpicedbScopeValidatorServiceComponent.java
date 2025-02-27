package org.wso2.carbon.identity.authz.spicedb.scopevalidator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.authz.spicedb.scopevalidator.SpicedbScopeValidator;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;

/**
 * OSGi Component for the Spicedb Authorization Service.
 */
@Component(
        name = "identity.application.authz.spicedb.ScopeValidator.component",
        immediate = true
)
public class SpicedbScopeValidatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(SpicedbScopeValidatorServiceComponent.class);

    /**
     * Method to activate the component.
     *
     * @param context Context of the component
     */
    @Activate
    protected void activate (ComponentContext context) {

        try {
            SpicedbScopeValidator spicedbScopeValidator = new SpicedbScopeValidator();
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(ScopeValidator.class, spicedbScopeValidator, null);
            LOG.debug("FGA scope validator for spiceDB bundle is activated");
        } catch (Throwable throwable) {
            LOG.error("Error while starting FGA scope validator for spiceDB component", throwable);
        }
    }

    /**
     * Method to deactivate the component.
     *
     * @param context Context of the component
     */
    @Deactivate
    protected void deactivate (ComponentContext context) {

        LOG.debug("FGA scope validator for spiceDB bundle is deactivated.");
    }
}

