package com.motionary.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        // Add interceptor to log requests and responses
        List<ClientHttpRequestInterceptor> interceptors = new ArrayList<>();
        interceptors.add(new LoggingInterceptor());
        restTemplate.setInterceptors(interceptors);

        return restTemplate;
    }

    private static class LoggingInterceptor implements ClientHttpRequestInterceptor {

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            logRequest(request, body);

            ClientHttpResponse response = execution.execute(request, body);

            // Wrap response to allow multiple reads of the body
            ClientHttpResponse bufferedResponse = new BufferedClientHttpResponse(response);

            logResponse(bufferedResponse);

            return bufferedResponse;
        }

        private void logRequest(HttpRequest request, byte[] body) {
            log.debug("=== HTTP Request ===");
            log.debug("URI: {}", request.getURI());
            log.debug("Method: {}", request.getMethod());
            log.debug("Headers: {}", request.getHeaders());
            if (body.length > 0) {
                String bodyStr = new String(body, StandardCharsets.UTF_8);
                // Don't log passwords
                if (bodyStr.contains("password=")) {
                    log.debug("Body: [Contains password - not logging]");
                } else {
                    log.debug("Body: {}", bodyStr);
                }
            }
        }

        private void logResponse(ClientHttpResponse response) throws IOException {
            log.debug("=== HTTP Response ===");
            log.debug("Status: {}", response.getStatusCode());
            log.debug("Headers: {}", response.getHeaders());

            byte[] bodyBytes = StreamUtils.copyToByteArray(response.getBody());
            if (bodyBytes.length > 0) {
                String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);
                log.debug("Body: {}", bodyStr);

                if (!response.getStatusCode().is2xxSuccessful()) {
                    log.error("ERROR Response Body: {}", bodyStr);
                }
            } else {
                log.debug("Body: [empty]");
            }
        }
    }

    /**
     * Wrapper to allow multiple reads of the response body
     */
    private static class BufferedClientHttpResponse implements ClientHttpResponse {
        private final ClientHttpResponse response;
        private byte[] body;

        public BufferedClientHttpResponse(ClientHttpResponse response) throws IOException {
            this.response = response;
            this.body = StreamUtils.copyToByteArray(response.getBody());
        }

        @Override
        public org.springframework.http.HttpStatusCode getStatusCode() throws IOException {
            return response.getStatusCode();
        }

        @Override
        public String getStatusText() throws IOException {
            return response.getStatusText();
        }

        @Override
        public void close() {
            response.close();
        }

        @Override
        public InputStream getBody() throws IOException {
            return new ByteArrayInputStream(body);
        }

        @Override
        public org.springframework.http.HttpHeaders getHeaders() {
            return response.getHeaders();
        }
    }
}