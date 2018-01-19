package org.wso2.carbon.identity.application.authenticator.samlsso;
/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import org.wso2.carbon.identity.application.authentication.framework.AuthenticationDataPublisher;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStateInfo;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.manager.DefaultSAML2SSOManager;
import org.wso2.carbon.identity.application.authenticator.samlsso.model.StateInfo;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class SAMLAuthenticationDataPublisher extends AbstractIdentityMessageHandler implements AuthenticationDataPublisher {

    private static Log log = LogFactory.getLog(SAMLAuthenticationDataPublisher.class);

    @Override
    public String getName() {
        return "SAMLAuthenticationDataPublisher";
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {
        return true;
    }

    @Override
    public void publishAuthenticationStepSuccess(HttpServletRequest httpServletRequest,
                                                 AuthenticationContext authenticationContext, Map<String, Object> map) {

    }

    @Override
    public void publishAuthenticationStepFailure(HttpServletRequest httpServletRequest,
                                                 AuthenticationContext authenticationContext, Map<String, Object> map) {

    }

    @Override
    public void publishAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                             AuthenticationContext authenticationContext, Map<String, Object> map) {

    }

    @Override
    public void publishAuthenticationFailure(HttpServletRequest httpServletRequest,
                                             AuthenticationContext authenticationContext, Map<String, Object> map) {

    }

    @Override
    public void publishSessionCreation(HttpServletRequest httpServletRequest, AuthenticationContext authenticationContext,
                                       SessionContext sessionContext, Map<String, Object> map) {
        if("SAMLSSOAuthenticator".equals(authenticationContext.getCurrentAuthenticatedIdPs().entrySet().iterator().next
                ().getValue().getAuthenticator().getName())) {
            AuthenticatorStateInfo authenticatorStateInfo = authenticationContext.getCurrentAuthenticatedIdPs().entrySet()
                    .iterator().next().getValue().getAuthenticator().getAuthenticatorStateInfo();
            String sessionIndex = ((StateInfo) authenticatorStateInfo).getSessionIndex();
            log.info("****** sessionIndex ****** " + sessionIndex);
            Object sessionId =  map.get(FrameworkConstants.AnalyticsAttributes.SESSION_ID);
            log.info("****** sessionID ****** " + sessionId);
            DefaultSAML2SSOManager.sessionIndexMap.put(sessionIndex, sessionId);
        }
    }

    @Override
    public void publishSessionUpdate(HttpServletRequest httpServletRequest, AuthenticationContext authenticationContext,
                                     SessionContext sessionContext, Map<String, Object> map) {

    }

    @Override
    public void publishSessionTermination(HttpServletRequest httpServletRequest,
                                          AuthenticationContext authenticationContext, SessionContext sessionContext,
                                          Map<String, Object> map) {

    }
}
