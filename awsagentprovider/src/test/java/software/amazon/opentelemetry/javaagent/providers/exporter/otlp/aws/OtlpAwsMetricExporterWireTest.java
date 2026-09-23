/*
 * Copyright Amazon.com, Inc. or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package software.amazon.opentelemetry.javaagent.providers.exporter.otlp.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.exporter.otlp.http.metrics.OtlpHttpMetricExporter;
import io.opentelemetry.sdk.metrics.export.MetricExporter;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.opentelemetry.javaagent.providers.exporter.otlp.aws.metrics.OtlpAwsMetricExporterBuilder;

/**
 * Wire-level tests that assert on the HTTP headers a server actually receives, rather than on which
 * exporter class the customizer returned.
 *
 * <p>These exist because upstream includes values from both {@code addHeader(...)} and {@code
 * setHeaders(Supplier)} when keys collide, so layering SigV4 on top of a configured bearer token
 * produces two {@code Authorization} values. These tests measure that exactly one {@code
 * Authorization} header reaches the server in each authentication mode.
 */
class OtlpAwsMetricExporterWireTest {

  private static final String ACCESS_KEY_ID_PROPERTY = "aws.accessKeyId";
  private static final String SECRET_ACCESS_KEY_PROPERTY = "aws.secretAccessKey";

  private HttpServer server;
  private final AtomicReference<List<String>> authorizationValues = new AtomicReference<>();
  private CountDownLatch requestReceived;
  private String previousAccessKeyId;
  private String previousSecretAccessKey;

  @BeforeEach
  void setUp() throws Exception {
    this.requestReceived = new CountDownLatch(1);
    this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    this.server.createContext(
        "/v1/metrics",
        exchange -> {
          this.authorizationValues.set(exchange.getRequestHeaders().get("Authorization"));
          exchange.sendResponseHeaders(200, 0);
          exchange.getResponseBody().close();
          this.requestReceived.countDown();
        });
    this.server.start();

    // Fake static credentials so the real signer produces a real signature without contacting AWS.
    this.previousAccessKeyId = System.getProperty(ACCESS_KEY_ID_PROPERTY);
    this.previousSecretAccessKey = System.getProperty(SECRET_ACCESS_KEY_PROPERTY);
    System.setProperty(ACCESS_KEY_ID_PROPERTY, "AKIAFAKEACCESSKEY123");
    System.setProperty(SECRET_ACCESS_KEY_PROPERTY, "fakeSecretAccessKeyForUnitTestsOnly");
  }

  @AfterEach
  void tearDown() {
    restoreProperty(ACCESS_KEY_ID_PROPERTY, this.previousAccessKeyId);
    restoreProperty(SECRET_ACCESS_KEY_PROPERTY, this.previousSecretAccessKey);
    if (this.server != null) {
      this.server.stop(0);
    }
  }

  private static void restoreProperty(String key, String previousValue) {
    if (previousValue == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, previousValue);
    }
  }

  private String endpoint() {
    return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/v1/metrics";
  }

  private List<String> exportAndCaptureAuthorization(MetricExporter exporter) throws Exception {
    exporter.export(Collections.emptyList()).join(10, TimeUnit.SECONDS);
    assertTrue(this.requestReceived.await(10, TimeUnit.SECONDS), "no request reached the server");
    return this.authorizationValues.get();
  }

  /**
   * Bearer mode: the user configured an Authorization header, so the customizer leaves the upstream
   * exporter unwrapped. Only the bearer value should reach the server.
   */
  @Test
  void testBearerTokenModeSendsExactlyOneAuthorizationHeader() throws Exception {
    OtlpHttpMetricExporter exporter =
        OtlpHttpMetricExporter.builder()
            .setEndpoint(endpoint())
            .addHeader("Authorization", "Bearer FAKE_METRICS_API_KEY")
            .build();

    List<String> received = exportAndCaptureAuthorization(exporter);

    assertNotNull(received, "no Authorization header received");
    assertEquals(1, received.size(), "expected exactly one Authorization header, got " + received);
    assertTrue(
        received.get(0).startsWith("Bearer "),
        "expected the bearer token to be preserved, got " + received.get(0));

    exporter.shutdown().join(5, TimeUnit.SECONDS);
  }

  /**
   * SigV4 mode: no Authorization header is configured, so the SigV4 wrapper applies. Only the SigV4
   * value should reach the server.
   */
  @Test
  void testSigV4ModeSendsExactlyOneAuthorizationHeader() throws Exception {
    OtlpHttpMetricExporter parentExporter =
        OtlpHttpMetricExporter.builder().setEndpoint(endpoint()).build();
    MetricExporter exporter =
        OtlpAwsMetricExporterBuilder.create(parentExporter, endpoint()).build();

    List<String> received = exportAndCaptureAuthorization(exporter);

    assertNotNull(received, "no Authorization header received");
    assertEquals(1, received.size(), "expected exactly one Authorization header, got " + received);
    assertTrue(
        received.get(0).startsWith("AWS4-HMAC-SHA256 "),
        "expected a SigV4 Authorization header, got " + received.get(0));
    assertTrue(
        received.get(0).contains("/monitoring/aws4_request"),
        "expected the monitoring signing service in the credential scope, got " + received.get(0));

    exporter.shutdown().join(5, TimeUnit.SECONDS);
  }

  /**
   * Regression guard for the duplicate-header problem: if a bearer token and the SigV4 wrapper are
   * combined, upstream sends two Authorization values. This documents the behavior the precedence
   * check in the customizer exists to prevent.
   */
  @Test
  void testCombiningBearerAndSigV4ProducesTwoAuthorizationHeaders() throws Exception {
    OtlpHttpMetricExporter parentExporter =
        OtlpHttpMetricExporter.builder()
            .setEndpoint(endpoint())
            .addHeader("Authorization", "Bearer FAKE_METRICS_API_KEY")
            .build();
    MetricExporter exporter =
        OtlpAwsMetricExporterBuilder.create(parentExporter, endpoint()).build();

    List<String> received = exportAndCaptureAuthorization(exporter);

    assertNotNull(received, "no Authorization header received");
    assertEquals(
        2, received.size(), "expected the documented duplicate-header behavior, got " + received);
  }
}
