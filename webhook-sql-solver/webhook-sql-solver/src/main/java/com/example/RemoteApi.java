package com.example;

import lombok.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
@RequiredArgsConstructor
public class RemoteApi {

  private final WebClient web;

  @Value("${endpoints.generate}")
  private String generateUrl;

  @Value("${app.name}")   private String name;
  @Value("${app.regNo}")  private String regNo;
  @Value("${app.email}")  private String email;

  public AppConfig getCfg() { return new AppConfig(name, regNo, email); }

  public GenerateWebhookResponse generateWebhook() {
    GenerateWebhookRequest body = new GenerateWebhookRequest(name, regNo, email);
    return web.post()
        .uri(generateUrl)
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(body)
        .retrieve()
        .bodyToMono(GenerateWebhookResponse.class)
        .block();
  }

  public void submitSolution(String webhookUrl, String accessToken, String finalQuery) {
    SubmitBody payload = new SubmitBody(finalQuery);
    web.post()
        .uri(webhookUrl)
        .contentType(MediaType.APPLICATION_JSON)
        .header("Authorization", accessToken)
        .bodyValue(payload)
        .retrieve()
        .toBodilessEntity()
        .block();
  }

  // DTOs
  public record AppConfig(String name, String regNo, String email) {}

  public record GenerateWebhookRequest(String name, String regNo, String email) {}

  @Getter @Setter @NoArgsConstructor @AllArgsConstructor
  public static class GenerateWebhookResponse {
    private String webhook;
    private String accessToken;
    public String getWebhook() { return webhook; }
    public String getAccessToken() { return accessToken; }
  }

  public record SubmitBody(String finalQuery) {}
}
