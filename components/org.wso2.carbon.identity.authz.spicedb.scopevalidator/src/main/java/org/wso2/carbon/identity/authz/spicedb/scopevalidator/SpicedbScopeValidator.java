package org.wso2.carbon.identity.authz.spicedb.scopevalidator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.fga.FGAuthorizationException;
import org.wso2.carbon.identity.oauth2.fga.factory.FGAuthorizationEngineFactory;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzActionObject;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzBulkCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckRequest;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzCheckResponse;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzResourceObject;
import org.wso2.carbon.identity.oauth2.fga.models.AuthzSubjectObject;
import org.wso2.carbon.identity.oauth2.fga.models.ErrorResponse;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsRequest;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsResponse;
import org.wso2.carbon.identity.oauth2.fga.models.ListObjectsResult;
import org.wso2.carbon.identity.oauth2.fga.services.FGAuthorizationInterface;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.identity.oauth2.validators.scope.ScopeValidator;

import java.util.ArrayList;

/**
 *
 */
public class SpicedbScopeValidator implements ScopeValidator {

    private static final Log LOG = LogFactory.getLog(SpicedbScopeValidator.class);
    private FGAuthorizationInterface authorizationService;

    public SpicedbScopeValidator() {
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext oAuthAuthzReqMessageContext)
            throws IdentityOAuth2Exception {

        try {
            authorizationService = FGAuthorizationEngineFactory.createServiceInstance().getAuthorizationService();
        } catch (Exception e) {
            throw new IdentityOAuth2Exception(e.getMessage());
        }
        ArrayList<String> requestedScopes = new ArrayList<>();
        ArrayList<String> authorizedScopes = new ArrayList<>();
        for (String scope : oAuthAuthzReqMessageContext.getRequestedScopes()) {
            if (scope.contains("fga")) {
                requestedScopes.add(scope);
            }
        }
        if (requestedScopes.size() == 1) {
            String scope = requestedScopes.get(0);
            String[] data = scope.split("_");
            if (data.length == 4) {
                AuthzCheckResponse checkResponse;
                try {
                    AuthzCheckRequest checkRequest =
                            createCheckRequest(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()
                                    .getUser().getUserId(), scope);
                    checkResponse = authorizationService.checkAuthorization(checkRequest);
                } catch (UserIdNotFoundException | FGAuthorizationException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
                if (checkResponse.isAuthorized()) {
                    authorizedScopes.add(scope);
                    oAuthAuthzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
                }
                return true;
            } else if (data.length == 3) {
                ListObjectsResponse listObjectsResponse;
                try {
                    ListObjectsRequest listObjectsRequest = createListObjectsRequest(data,
                            oAuthAuthzReqMessageContext.getAuthorizationReqDTO().getUser().getUserId());
                    listObjectsResponse = authorizationService.lookUpResources(listObjectsRequest);
                } catch (UserIdNotFoundException | FGAuthorizationException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
                authorizedScopes.addAll(getListResults(listObjectsResponse,
                        requestedScopes));
                oAuthAuthzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
                return true;
            }
        } else if (requestedScopes.size() > 1) {
            ArrayList<AuthzCheckRequest> items = new ArrayList<>();
            for (String scope : requestedScopes) {
                try {
                    items.add(createCheckRequest(oAuthAuthzReqMessageContext.getAuthorizationReqDTO()
                            .getUser().getUserId(), scope));
                } catch (UserIdNotFoundException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
            }
            AuthzBulkCheckRequest bulkCheckRequest = new AuthzBulkCheckRequest(items);
            AuthzBulkCheckResponse bulkCheckResponse;
            try {
                bulkCheckResponse = authorizationService
                        .bulkCheckAuthorization(bulkCheckRequest);
            } catch (FGAuthorizationException e) {
                throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
            }
            authorizedScopes.addAll(getBulkAuthorization(bulkCheckResponse,
                    requestedScopes));
            oAuthAuthzReqMessageContext.setApprovedScope(authorizedScopes.toArray(new String[0]));
            return true;
        }

        return false;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)
            throws IdentityOAuth2Exception {

        ArrayList<String> requestedScopes = new ArrayList<>();
        ArrayList<String> authorizedScopes = new ArrayList<>();
        for (String scope : oAuthTokenReqMessageContext.getScope()) {
            if (scope.contains("fga")) {
                requestedScopes.add(scope);
            }
        }
        if (requestedScopes.size() == 1) {
            String scope = requestedScopes.get(0);
            String[] data = scope.split("_");
            if (data.length == 4) {
                AuthzCheckResponse checkResponse;
                try {
                    checkResponse = authorizationService.checkAuthorization(
                            createCheckRequest(oAuthTokenReqMessageContext.getAuthorizedUser().getUserId(),
                                    scope));
                } catch (UserIdNotFoundException | FGAuthorizationException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
                if (checkResponse.isAuthorized()) {
                    authorizedScopes.add(scope);
                    oAuthTokenReqMessageContext.setAuthorizedInternalScopes(authorizedScopes.toArray(new String[0]));
                }
                return true;
            } else if (data.length == 3) {
                ListObjectsResponse listObjectsResponse;
                try {
                    ListObjectsRequest listObjectsRequest = createListObjectsRequest(data,
                            oAuthTokenReqMessageContext.getAuthorizedUser().getUserId());
                    listObjectsResponse = authorizationService.lookUpResources(listObjectsRequest);
                } catch (UserIdNotFoundException | FGAuthorizationException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
                authorizedScopes.addAll(getListResults(listObjectsResponse,
                        requestedScopes));
                oAuthTokenReqMessageContext.setAuthorizedInternalScopes(authorizedScopes.toArray(new String[0]));
                return true;
            }
        } else if (requestedScopes.size() > 1) {
            ArrayList<AuthzCheckRequest> items = new ArrayList<>();
            for (String scope : requestedScopes) {
                try {
                    items.add(createCheckRequest(oAuthTokenReqMessageContext.getAuthorizedUser().getUserId(), scope));
                } catch (UserIdNotFoundException e) {
                    throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
                }
            }
            AuthzBulkCheckRequest bulkCheckRequest = new AuthzBulkCheckRequest(items);
            AuthzBulkCheckResponse bulkCheckResponse;
            try {
                bulkCheckResponse = authorizationService
                        .bulkCheckAuthorization(bulkCheckRequest);
            } catch (FGAuthorizationException e) {
                throw new IdentityOAuth2Exception(e.getErrorCode(), e.getMessage());
            }
            authorizedScopes.addAll(getBulkAuthorization(bulkCheckResponse,
                    requestedScopes));
            oAuthTokenReqMessageContext.setAuthorizedInternalScopes(authorizedScopes.toArray(new String[0]));
            return true;
        }

        return false;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext oAuth2TokenValidationMessageContext)
            throws IdentityOAuth2Exception {

        return false;
    }

    @Override
    public String getName() {

        return "SpiceDbScopeValidator";
    }

    private AuthzCheckRequest createCheckRequest(String userId, String scope) {

        String[] data = scope.split("_");
        String permission = data[1];
        String resourceType = data[2];
        String resourceId = data[3];
        AuthzSubjectObject subject = new AuthzSubjectObject("user", userId);
        AuthzActionObject action = new AuthzActionObject(permission);
        AuthzResourceObject resource = new AuthzResourceObject(resourceType, resourceId);
        return new AuthzCheckRequest(subject, action, resource);
    }

    private ArrayList<String> getBulkAuthorization(AuthzBulkCheckResponse bulkCheckResponse,
                                                   ArrayList<String> requiredScopes) {

        ArrayList<String> authorizedScopes = new ArrayList<>();
        for (String scope : requiredScopes) {
            String checkedResource = scope.split("_")[3];
            if (bulkCheckResponse.getResults().containsKey(checkedResource)) {
                AuthzCheckResponse item = bulkCheckResponse.getResults().get(checkedResource);
                if (item.isAuthorized()) {
                    authorizedScopes.add(scope);
                }
            } else if (bulkCheckResponse.getErrorResults().containsKey(checkedResource)) {
                LOG.error("Could not authorize " + checkedResource + ". " +
                        "Error: " + bulkCheckResponse.getErrorResults().get(checkedResource).getErrorMessage());
            }

        }
        return authorizedScopes;
    }

    private ListObjectsRequest createListObjectsRequest(String[] data, String userId) {

        String relation = data[1];
        String resourceType = data[2];
        return new ListObjectsRequest(resourceType, relation, "user", userId);
    }

    private ArrayList<String> getListResults(ListObjectsResponse listObjectsResponse,
                                             ArrayList<String> requiredScopes) {

        ArrayList<String> results = new ArrayList<>();
        for (ListObjectsResult resource : listObjectsResponse.getResults()) {
            results.add(requiredScopes.get(0) + "_" + resource.getResultObjectId());
        }
        for (ErrorResponse error : listObjectsResponse.getErrorResults()) {
            LOG.error("Cannot retrieve item from spiceDB." + error.getErrorCode() + error.getErrorMessage());
        }
        return results;
    }
}
