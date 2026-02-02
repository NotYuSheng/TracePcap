package com.tracepcap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for TracePcap - PCAP Analysis Tool
 *
 * <p>Features: - PCAP file upload and storage (MinIO) - Network traffic analysis - Protocol
 * distribution analysis - Conversation extraction - Timeline visualization - AI-powered narrative
 * generation
 *
 * @author TracePcap Team
 * @version 1.0.0
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class TracepcapApplication {

  public static void main(String[] args) {
    SpringApplication.run(TracepcapApplication.class, args);
  }
}
