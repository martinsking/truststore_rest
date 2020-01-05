import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.JettySettings;
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.AdminRequestHandler;
import com.github.tomakehurst.wiremock.http.HttpServer;
import com.github.tomakehurst.wiremock.http.HttpServerFactory;
import com.github.tomakehurst.wiremock.http.StubRequestHandler;
import com.github.tomakehurst.wiremock.jetty9.JettyHttpServer;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.eclipse.jetty.io.NetworkTrafficListener;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static com.github.tomakehurst.wiremock.client.WireMock.*;


public class RestTest {



    /* api header constants */

    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_JSON = "application/json;charset=utf-8";
    public static String WORKING_KEYSTORE = "C:\\Dev\\BAE\\Orion\\keystores\\self_signed\\working.jks"; //changeit
    public static String WORKING_KEYSTORE_PKCS12 = "/Users/mking/3tb-1-Martin/work/keystore/keystore.pkcs12";
    public static String WORKING_TRUSTSTORE = "/Users/mking/3tb-1-Martin/work/keystore/truststore.ts";
    public static Options options = WireMockConfiguration.options()
            .bindAddress("localhost")
            .port(8088)
            .httpsPort(8443)
            .httpServerFactory(new Pkcs12FriendlyHttpsServerFactory()) //needed for pkcs12
            .keystorePath(WORKING_KEYSTORE_PKCS12)
            .keystoreType("pkcs12")
            .keystorePassword("changeit");

    public static final WireMockServer wireMockServer = new WireMockServer(options);

    public static void main(String[] args)
            throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, IOException,
            CertificateException {
        wireMockServer.start();
        configureFor("https", "localhost", 8443);
        setUpGetMock("/test", 200, "I'm a response");
        //RestTemplate restTemplate = createSslRestTemplate(getAllTrustingSslContext());
        RestTemplate restTemplate = createSslRestTemplate(getSslContextFromTrustStore(
                WORKING_TRUSTSTORE, "changeit"));
        ResponseEntity<String> response = restTemplate.getForEntity("https://localhost:8443/test", String.class);
        System.out.println(response.toString());
        wireMockServer.stop();
    }


    /**
     * Sets up a wiremock endpoint response mapping acting as the Tasking Service.
     *
     * @param endpoint     - the endpoint for the mock
     * @param statusCode   - the status code that the mock should return
     * @param bodyAsString - the body (json string) that the mock should respond with
     */

    private static void setUpGetMock(final String endpoint,
                                     final int statusCode, final String bodyAsString) {
        stubFor(get(urlEqualTo(endpoint))
                .willReturn(aResponse()
                        .withStatus(statusCode)
                        .withHeader(CONTENT_TYPE, APPLICATION_JSON)
                        .withBody(bodyAsString)));
    }

    /**
     * Create rest templates for trying to make https requests.
     *
     * @Return RestTemplate (with trust all certs set)
     */

    private static RestTemplate createSslRestTemplate(SSLContext sslContext) {
        SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext,
                NoopHostnameVerifier.INSTANCE);
        Registry<ConnectionSocketFactory> socketFactoryRegistry =
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", csf)
                        .register("http", new PlainConnectionSocketFactory())
                        .build();

        BasicHttpClientConnectionManager connectionManager =
                new BasicHttpClientConnectionManager(socketFactoryRegistry);

        // create the https client to configure rest template with.
        final CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(csf)
                .setConnectionManager(connectionManager)
                .build();

        // create a ssl rest template.

        final HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory();
        requestFactory.setHttpClient(httpClient);
        return new RestTemplate(requestFactory);
    }

    private static SSLContext getSslContextFromKeystore(final String keystore, final String password)
            throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException,
            KeyStoreException, KeyManagementException {

        return SSLContextBuilder
                .create()
                .loadKeyMaterial(ResourceUtils.getFile("classpath:" + keystore), password.toCharArray(),
                        password.toCharArray())
                .build();
    }


    private static SSLContext getSslContextFromTrustStore(final String trustStore, final String password)
            throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException,
            KeyManagementException {

        return SSLContextBuilder
                .create()
                .loadTrustMaterial(ResourceUtils.getFile(trustStore), password.toCharArray())
                .build();
    }


    private static SSLContext getAllTrustingSslContext()
            throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        // set up ssl properties on the request to accept any certificate the server gives us.
        final TrustStrategy acceptingTrustStrategy = (final X509Certificate[] chain, final String authType) -> true;
        return SSLContexts.custom()
                .loadTrustMaterial(null, acceptingTrustStrategy)
                .build();
    }
}


class Pkcs12FriendlyHttpsServerFactory implements HttpServerFactory {

    @Override
    public HttpServer buildHttpServer(Options options, AdminRequestHandler adminRequestHandler, StubRequestHandler stubRequestHandler) {
        return new JettyHttpServer(
                options,
                adminRequestHandler,
                stubRequestHandler
        ) {
            @Override
            protected ServerConnector createServerConnector(String bindAddress, JettySettings jettySettings, int port, NetworkTrafficListener listener, ConnectionFactory... connectionFactories) {
                if (port == options.httpsSettings().port()) {
                    SslConnectionFactory sslConnectionFactory = (SslConnectionFactory) connectionFactories[0];
                    sslConnectionFactory.getSslContextFactory().setKeyStorePassword(options.httpsSettings().keyStorePassword());
                    connectionFactories = new ConnectionFactory[]{sslConnectionFactory, connectionFactories[1]};
                }
                return super.createServerConnector(bindAddress, jettySettings, port, listener, connectionFactories);
            }
        };


    }

}