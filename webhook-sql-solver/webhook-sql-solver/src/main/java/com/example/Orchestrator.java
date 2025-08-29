package com.example;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class Orchestrator {
  private final RemoteApi api;
  private final SqlSolver solver;

  public void execute() {
    // 1) Generate webhook
    RemoteApi.GenerateWebhookResponse resp = api.generateWebhook();
    if (resp == null) {
      log.error("No response from generateWebhook.");
      return;
    }
    log.info("Webhook: {}", resp.getWebhook());
    log.info("AccessToken received (trimmed).");

    // 2) Solve SQL based on regNo last two digits
    String regNo = api.getCfg().regNo();
    String digits = regNo.replaceAll("\\D", "");
    int lastTwo = 0;
    if (digits.length() > 0) {
      lastTwo = Integer.parseInt(digits);
      lastTwo = lastTwo % 100;
    }
    String finalQuery = solver.solve(lastTwo);
    log.info("Final SQL chosen:\n{}", finalQuery);

    // 3) Submit to webhook with Authorization header = accessToken (as-is)
    api.submitSolution(resp.getWebhook(), resp.getAccessToken(), finalQuery);
    log.info("Solution submitted.");
  }
}
