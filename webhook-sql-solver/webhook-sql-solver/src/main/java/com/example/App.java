package com.example;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class App {

  public static void main(String[] args) { SpringApplication.run(App.class, args); }

  @Bean
  WebClient webClient(WebClient.Builder b) {
    return b.build();
  }

  @Bean
  CommandLineRunner run(Orchestrator orchestrator) {
    return args -> orchestrator.execute();
  }
}
