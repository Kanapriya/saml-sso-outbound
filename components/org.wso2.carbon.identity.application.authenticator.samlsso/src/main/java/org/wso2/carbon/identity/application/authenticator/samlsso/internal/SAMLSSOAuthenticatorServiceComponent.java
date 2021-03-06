/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAML2FederatedLogoutRequestHandler;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAMLAuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authenticator.samlsso.SAMLSSOAuthenticator;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.osgi.service.http.HttpService;

import javax.servlet.Servlet;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.component name="identity.application.authenticator.samlsso.component" immediate="true"
 */

public class SAMLSSOAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(SAMLSSOAuthenticatorServiceComponent.class);
    private static String postPage = null;
    private static HttpService service = null;

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the SAML2 SSO Authenticator bundle");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(realmService);
    }

    public static String getPostPage() {
        return postPage;
    }

    protected void activate(ComponentContext ctxt) {
        String postPagePath = null;
        FileInputStream fis = null;
        try
        {
            Servlet samlSSOServlet = new ContextPathServletAdaptor(new SAML2FederatedLogoutRequestHandler(), "/fedlogout");
            try
            {
                service.registerServlet("/fedlogout", samlSSOServlet, null, null);
            } catch (Exception e) {
                String errMsg = "Error when registering SAML SSO Servlet via the HttpService.";
                log.error(errMsg, e);
                throw new RuntimeException(errMsg, e);
            }

            SAMLSSOAuthenticator samlSSOAuthenticator = new SAMLSSOAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), samlSSOAuthenticator, null);
            log.info("---------- Servlet Registering -----------");
            ctxt.getBundleContext().registerService(AuthenticationDataPublisher.class.getName(), new SAMLAuthenticationDataPublisher(), null);
            log.info("--------------------- data publisher ------ ");
            postPagePath = CarbonUtils.getCarbonHome() + File.separator + "repository"
                    + File.separator + "resources" + File.separator + "identity" + File.separator + "pages" + File
                    .separator + "samlsso_federate.html";
            fis = new FileInputStream(new File(postPagePath));
            postPage = new Scanner(fis, "UTF-8").useDelimiter("\\A").next();
            if (log.isDebugEnabled()) {
                log.info("SAML2 SSO Authenticator bundle is activated");
            }
        } catch (FileNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find SAMLSSO POST page for federation in "+ postPagePath);
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed SAMLSSO authentication" + e);
            }
        } finally {
            IdentityIOStreamUtils.closeInputStream(fis);
        }


    }

    protected void setHttpService(HttpService httpService)
    {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the SAML SSO bundle");
        }
        service = httpService;
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the SAML SSO bundle");
        }

        service = null;
    }


    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.info("SAML2 SSO Authenticator bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the SAML2 SSO Authenticator bundle");
        }
        SAMLSSOAuthenticatorServiceDataHolder.getInstance().setRealmService(null);
    }
}
