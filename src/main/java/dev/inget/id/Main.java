package dev.inget.id;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.inget.id.sslsupport.PEMTrustManager;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        BankIDEnvironment environment = null;
        String environmentHelp = null;
        String personalNumber = null;
        boolean supportsSpecial = false;
        final Scanner scanner = new Scanner(System.in);

        while (true) {
            while (true) {
                System.out.println("What environment do you want to use? 1=BankID test, 2=IngetID remote, 3=IngetID local, l=last, q=quit");
                String environmentChoice = scanner.next();
                if (environmentChoice.equals("1")) {
                    environment = createBankIDOfficialTestEnvironment();
                    environmentHelp = "Open a BankID app configured to use the official test environment and this personal number.";
                } else if (environmentChoice.equals("2")) {
                    environment = createIngetIDRemoteEnvironment();
                    environmentHelp = "See the admin UI at " + environment.appURL + "/admin";
                    supportsSpecial = true;
                } else if (environmentChoice.equals("3")) {
                    System.out.println("(remember to run blankid or blankid.exe)");
                    environment = createIngetIDLocalEnvironment();
                    environmentHelp = "See the admin UI at " + environment.appURL + "/admin";
                    supportsSpecial = true;
                } else if (environmentChoice.equals("l")) {
                    // do nothing
                } else if (environmentChoice.equals("q")) {
                    System.exit(0);
                } else {
                    continue;
                }
                if (environment == null) {
                    continue;
                }
                break;
            }

            while (true) {
                System.out.println("What personal number do you want to use? l=last, q=quit");
                if (supportsSpecial) {
                    System.out.println("Special suffixes: ic=immediate complete, pc=pending complete");
                    System.out.println(" - immediate complete will complete flow immediately, example 123ic");
                    System.out.println(" - pending complete will complete flow after one collect, example 123pc");
                }
                String personalNumberChoice = scanner.next();
                if (personalNumberChoice.equals("l")) {
                    // do nothing
                } else if (personalNumberChoice.equals("q")) {
                    System.exit(0);
                } else {
                    personalNumber = personalNumberChoice;
                }

                if (personalNumber == null || personalNumber.equals("")) {
                    continue;
                }

                personalNumber = personalNumber.replaceAll("[^a-zA-Z0-9]+", "");
                break;
            }

            if (environmentHelp != null) {
                System.out.println(environmentHelp);
            }

            Collect authCollect = environment.performAuth(personalNumber);
            System.out.println(authCollect);
            System.out.println("It worked!");
            System.out.println();
            System.out.println();
        }
    }

    static BankIDEnvironment createIngetIDLocalEnvironment() throws Exception {
        final String appURL = "http://127.0.0.1:6080";
        final String baseURL = "https://127.0.0.1:6081";
        final String dataPath = "inget-id-local";
        return createIngetIDEnvironment(appURL, baseURL, dataPath);
    }

    static BankIDEnvironment createIngetIDRemoteEnvironment() throws Exception {
        final String appURL = "https://ingetid.fly.dev";
        final String baseURL = "https://ingetid.fly.dev:6081";
        final String dataPath = "inget-id-remote";
        return createIngetIDEnvironment(appURL, baseURL, dataPath);
    }

    static BankIDEnvironment createIngetIDEnvironment(String appURL, String baseURL, String dataPath) throws Exception {
        final String password = "hej123";
        final String clientPKCS12Path = dataPath + "/client.p12";
        final String serverPEMPath = dataPath + "/server.pem";

        HttpClient downloadClient = HttpClient.newHttpClient();

        HttpResponse<Path> clientPKCS12Response = downloadClient.send(
                HttpRequest.newBuilder()
                        .GET()
                        .uri(URI.create(appURL + "/_session/client.p12?passphrase=" + password))
                        .build(),
                HttpResponse.BodyHandlers.ofFile(new File(clientPKCS12Path).toPath()));

        if (clientPKCS12Response.statusCode() != 200) {
            throw new IOException("could not download client certificate");
        }

        HttpResponse<Path> serverPEMResponse = downloadClient.send(
                HttpRequest.newBuilder()
                        .GET()
                        .uri(URI.create(appURL + "/_session/server.pem"))
                        .build(),
                HttpResponse.BodyHandlers.ofFile(new File(serverPEMPath).toPath()));

        if (serverPEMResponse.statusCode() != 200) {
            throw new IOException("could not server certificate");
        }

        HttpClient client = buildClient(password, clientPKCS12Path, serverPEMPath);

        return new BankIDEnvironment(client, baseURL, appURL);
    }

    static BankIDEnvironment createBankIDOfficialTestEnvironment() throws Exception {
        final String appURL = "https://app.bankid.com/";
        final String baseURL = "https://appapi2.test.bankid.com";
        HttpClient client = buildClient("qwerty123", "bankid-official-test/FPTestcert4_20220818.p12", "bankid-official-test/issuer.pem");

        return new BankIDEnvironment(client, baseURL, appURL);
    }

    static HttpClient buildClient(String password, String PKCS12Path, String issuerPEMPath) throws Exception {
        final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");

        final KeyStore clientStore = KeyStore.getInstance("PKCS12");
        clientStore.load(new FileInputStream(PKCS12Path), password.toCharArray());
        final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(clientStore, password.toCharArray());

        final String issuerPEM = Files.readString(new File(issuerPEMPath).toPath());
        final TrustManager trustManager = new PEMTrustManager(issuerPEM);
        sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[]{trustManager}, null);

        return HttpClient.newBuilder().sslContext(sslContext).build();
    }

    static class BankIDEnvironment {

        final HttpClient httpClient;
        final String baseURL;
        final String appURL;

        BankIDEnvironment(HttpClient httpClient, String baseURL, String appURL) {
            this.httpClient = httpClient;
            this.baseURL = baseURL;
            this.appURL = appURL;
        }

        Collect performAuth(String personalNumber) throws Exception {
            final HttpRequest authRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(
                            new AuthRequestBody("1.2.3.4", personalNumber)
                    )))
                    .header("content-type", "application/json")
                    .uri(URI.create(baseURL + "/rp/v5.1/auth"))
                    .build();

            HttpResponse<String> authResponse = httpClient.send(authRequest, HttpResponse.BodyHandlers.ofString());

            if (authResponse.statusCode() != 200) {
                throw new Exception(String.format("auth request failed (HTTP status %d): %s", authResponse.statusCode(), authResponse.body()));
            }

            AuthResponseBody authResponseBody = objectMapper.readValue(authResponse.body(), AuthResponseBody.class);
            System.out.println(authResponseBody);

            Collect collect;
            while (true) {
                Thread.sleep(2000);
                collect = collect(authResponseBody.orderRef);
                if (collect.statusCode != 200) {
                    break;
                }
                if (collect.body != null && !collect.body.status.equals("pending")) {
                    break;
                }
            }

            return collect;
        }

        Collect collect(String orderRef) throws Exception {
            final HttpRequest collectRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(
                            new CollectRequestBody(orderRef)
                    )))
                    .header("content-type", "application/json")
                    .uri(URI.create(baseURL + "/rp/v5.1/collect"))
                    .build();

            HttpResponse<String> collectResponse = httpClient.send(collectRequest, HttpResponse.BodyHandlers.ofString());
            System.out.printf("collect response (HTTP status %d): %s\n", collectResponse.statusCode(), collectResponse.body());

            CollectResponseBody collectResponseBody = null;
            if (collectResponse.statusCode() == 200) {
                collectResponseBody = objectMapper.readValue(collectResponse.body(), CollectResponseBody.class);
            }
            return new Collect(collectResponse.statusCode(), collectResponseBody);
        }

    }

    record AuthRequestBody(String endUserIp, String personalNumber) {}
    record AuthResponseBody(String orderRef, String autoStartToken, String qrStartToken, String qrStartSecret) {}

    record CollectRequestBody(String orderRef) {}
    record CollectResponseBody(String orderRef, String status, String hintCode) {}
    record Collect(int statusCode, CollectResponseBody body) {}

    final static ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
}