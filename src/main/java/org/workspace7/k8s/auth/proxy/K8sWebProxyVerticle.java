/*
 *   Copyright 2016 Kamesh Sampath
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package org.workspace7.k8s.auth.proxy;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.http.*;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.JksOptions;
import io.vertx.core.net.PemKeyCertOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.OAuth2FlowType;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.OAuth2AuthHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * TODO handle HTTPS
 */
public class K8sWebProxyVerticle extends AbstractVerticle {

    private static final Logger _logger = LoggerFactory.getLogger(K8sWebProxyVerticle.class.getName());
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_FORMAT = "Bearer %s";

    @Override
    public void start(Future<Void> startFuture) throws Exception {

        setup((keyCloakOAuth2) -> startWebApp(keyCloakOAuth2,
                (http) -> completeStatup(http, startFuture))
                , startFuture);
    }

    /**
     * @param keyCloakOAuth2
     * @param next
     */
    protected void startWebApp(AsyncResult<OAuth2Auth> keyCloakOAuth2,
                               Handler<AsyncResult<HttpServer>> next) {

        Router router = Router.router(vertx);

        final String proxyUri = "https://" + config().getString("k8s_proxy_host")
                + ":" + config().getInteger("k8s_proxy_port");

        if (keyCloakOAuth2.succeeded()) {

            OAuth2AuthHandler keycloakOAuthHandler = OAuth2AuthHandler.create(keyCloakOAuth2.result(), proxyUri);
            keycloakOAuthHandler.setupCallback(router.get("/callback"));

            router.route("/api/*").handler(keycloakOAuthHandler);

            //Handle UI Requests
            router.route("/api/ui/").handler(this::handleUIPath);

            //Handle API Requests
            router.route("/api/").handler(this::handleApiPath);

            //TODO - do we redirect it to /api/ui or api ?
            router.get("/").handler(ctx -> ctx.reroute("/api"));

            //These options are for setting up the server (k8s-proxy)
            HttpServerOptions httpServerOptions = new HttpServerOptions().setSsl(true);

            //Server HTTPS
            httpServerOptions.setPemKeyCertOptions(proxyPemOptions());
            httpServerOptions.setTrustStoreOptions(proxyTrustOptions());

            vertx.createHttpServer(httpServerOptions).requestHandler(router::accept)
                    .listen(config().getInteger("k8s_proxy_port"),
                            config().getString("k8s_proxy_host"), next);
        } else {
            _logger.error("Unable to start proxy : {}", keyCloakOAuth2.cause());
            next.handle(Future.failedFuture(keyCloakOAuth2.cause()));
        }
    }

    @Override
    public void stop(Future<Void> stopFuture) throws Exception {
        stopFuture.complete();
    }

    protected void completeStatup(AsyncResult<HttpServer> httpServer, Future<Void> future) {
        if (httpServer.succeeded()) {
            _logger.info("Successfully started Proxy Server");
            future.complete();
        } else {
            _logger.error("Error starting HTTP Server {}", httpServer.cause());
            future.fail(httpServer.cause());
        }
    }

    /**
     * TODO documentation and better exception handling
     *
     * @param routingContext
     */
    protected void handleApiPath(RoutingContext routingContext) {

        HttpServerRequest request = routingContext.request();
        HttpServerResponse response = routingContext.response();

        JsonObject userPrincipal = routingContext.user().principal();
        _logger.trace("User Principal:{}" + userPrincipal);

        final String accessToken = userPrincipal.getString("id_token");
        final String authHeader = String.format(BEARER_FORMAT, accessToken);

        _logger.debug("Proxying Request to K8s Master :{} with method {}",
                request.uri(), request.method());

        HttpClient k8HttpClient = vertx.createHttpClient(apiServerClientOptions());

        //Proxying request to Kubernetes Master
        HttpClientRequest k8sClientRequest = k8HttpClient.request(request.method(),
                config().getInteger("k8s_master_port"),
                config().getString("k8s_master_host"),
                request.uri(), k8sApiResp -> {
                    k8sApiResp.exceptionHandler(event -> {
                        _logger.error("Error while calling Kubernetes :", event.getCause());
                    });

                    response.setChunked(true);
                    response.setStatusCode(k8sApiResp.statusCode());
                    response.headers().setAll(k8sApiResp.headers());
                    k8sApiResp.handler(data -> {
                        _logger.debug("Proxying Resp Body:{}", data.toString());
                        response.write(data);
                    });

                    k8sApiResp.endHandler((v) -> response.end());
                });

        k8sClientRequest.setChunked(true);
        //Add Required Headers to k8s
        k8sClientRequest.headers().set(AUTHORIZATION_HEADER, authHeader);

        request.handler(data -> k8sClientRequest.write(Json.encodePrettily(data)));

        k8sClientRequest.exceptionHandler(ex -> {
            _logger.error("Error while calling Kubernetes API", ex);
            response.setStatusCode(503).end();
        });

        k8sClientRequest.end();
    }

    /**
     * TODO: Doc and better exception handling
     *
     * @param routingContext
     */
    protected void handleUIPath(RoutingContext routingContext) {

        HttpServerRequest request = routingContext.request();
        HttpServerResponse response = routingContext.response();

        JsonObject userPrincipal = routingContext.user().principal();
        _logger.trace("User Principal:{}" + userPrincipal);

        final String accessToken = userPrincipal.getString("id_token");
        final String authHeader = String.format(BEARER_FORMAT, accessToken);

        _logger.debug("Proxying Request to K8s Master :{} with method {}",
                request.uri(), request.method());

        HttpClient k8HttpClient = vertx.createHttpClient(apiServerClientOptions());

        HttpClientRequest k8sClientRequest = k8HttpClient.get(config().getInteger("k8s_master_port"),
                config().getString("k8s_master_host"),"/swaggerui");
        k8sClientRequest.headers().set(AUTHORIZATION_HEADER, authHeader);

        k8sClientRequest.exceptionHandler(ex -> {
            _logger.error("Error while calling Kubernetes API", ex);
            response.setStatusCode(503).end();
        });

    }

    protected void setup(Handler<AsyncResult<OAuth2Auth>> next, Future<Void> future) {

        final OAuth2ClientOptions options = new OAuth2ClientOptions();
        options.setSsl(true);
        options.setTrustStoreOptions(proxyTrustOptions());

        // keycloak conversion to oauth2 options
        if (config().containsKey("auth-server-url")) {
            options.setSite(config().getString("auth-server-url"));
        }

        if (config().containsKey("resource")) {
            options.setClientID(config().getString("resource"));
        }

        if (config().containsKey("credentials")
                && config().getJsonObject("credentials").containsKey("secret")) {
            options.setClientSecret(config().getJsonObject("credentials").getString("secret"));
        }

        if (config().containsKey("public-client")
                && config().getBoolean("public-client", false)) {
            options.setUseBasicAuthorizationHeader(true);
        }

        if (config().containsKey("realm")) {
            final String realm = config().getString("realm");

            options.setAuthorizationPath("/realms/" + realm + "/protocol/openid-connect/auth");
            options.setTokenPath("/realms/" + realm + "/protocol/openid-connect/token");
            options.setRevocationPath(null);
            options.setLogoutPath("/realms/" + realm + "/protocol/openid-connect/logout");
            options.setUserInfoPath("/realms/" + realm + "/protocol/openid-connect/userinfo");
        }

        if (config().containsKey("realm-public-key")) {
            options.setPublicKey(config().getString("realm-public-key"));
            options.setJwtToken(true);
        }

        OAuth2Auth keycloakOAuth2 = OAuth2Auth.create(vertx,
                OAuth2FlowType.AUTH_CODE, options);

        next.handle(Future.succeededFuture(keycloakOAuth2));

    }

    private JksOptions proxyTrustOptions() {

        return new JksOptions()
                .setPath(config().getString("keystore-path"))
                .setPassword(config().getString("keystore-password"));

    }

    private JksOptions apiServerTrustOptions() {

        return new JksOptions()
                .setPath(config().getString("k8s_apiserver_keystore-path"))
                .setPassword(config().getString("k8s_apiserver_keystore-password"));
    }

    private PemKeyCertOptions proxyPemOptions() {
        return new PemKeyCertOptions()
                .setCertPath(config().getString("cert-path"))
                .setKeyPath(config().getString("key-path"));

    }

    private HttpClientOptions apiServerClientOptions() {
        return new HttpClientOptions().setSsl(true).setTrustStoreOptions(apiServerTrustOptions());
    }

}