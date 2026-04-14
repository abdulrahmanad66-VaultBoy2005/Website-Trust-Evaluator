package com.safetypro.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;

@Service
public class WhoisApiService {

    @Value("${whois.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public WhoisApiService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    public Map<String, Object> getWhoisInfo(String domain) {
        Map<String, Object> result = new HashMap<>();

        try {
            // Clean domain
            domain = domain.replace("https://", "")
                    .replace("http://", "")
                    .replace("www.", "")
                    .split("/")[0];

            System.out.println("🔍 Fetching WHOIS data for: " + domain);

            String url = "https://api.ip2whois.com/v2?key=" + apiKey + "&domain=" + domain;

            String response = restTemplate.getForObject(url, String.class);
            JsonNode root = objectMapper.readTree(response);

            // Basic Domain Info
            result.put("domain", getString(root, "domain"));
            result.put("domain_id", getString(root, "domain_id"));
            result.put("status", getString(root, "status"));
            result.put("whois_server", getString(root, "whois_server"));
            result.put("domain_age", root.has("domain_age") ? root.get("domain_age").asInt() : 0);

            // Dates
            result.put("create_date", formatDate(getString(root, "create_date")));
            result.put("update_date", formatDate(getString(root, "update_date")));
            result.put("expire_date", formatDate(getString(root, "expire_date")));

            // Registrar Info
            if (root.has("registrar")) {
                JsonNode registrar = root.get("registrar");
                Map<String, String> registrarMap = new HashMap<>();
                registrarMap.put("iana_id", getString(registrar, "iana_id"));
                registrarMap.put("name", getString(registrar, "name"));
                registrarMap.put("url", getString(registrar, "url"));
                result.put("registrar", registrarMap);
            }

            // Registrant (Owner) Info
            if (root.has("registrant")) {
                JsonNode registrant = root.get("registrant");
                Map<String, String> registrantMap = new HashMap<>();
                registrantMap.put("organization", getString(registrant, "organization"));
                registrantMap.put("country", getString(registrant, "country"));
                registrantMap.put("email", getString(registrant, "email"));
                registrantMap.put("name", getString(registrant, "name"));
                registrantMap.put("phone", getString(registrant, "phone"));
                result.put("registrant", registrantMap);
            }

            // Name Servers
            if (root.has("nameservers") && root.get("nameservers").isArray()) {
                result.put("nameservers", root.get("nameservers"));
            }

            System.out.println("✅ WHOIS data retrieved for " + domain);

        } catch (Exception e) {
            System.err.println("❌ WHOIS API error: " + e.getMessage());
            result.put("error", e.getMessage());
        }

        return result;
    }

    private String getString(JsonNode node, String field) {
        return node.has(field) && !node.get(field).isNull() ? node.get(field).asText() : "";
    }

    private String formatDate(String dateStr) {
        if (dateStr == null || dateStr.isEmpty()) return "";
        // Remove time part if present (e.g., "1997-09-15T07:00:00+0000" -> "1997-09-15")
        if (dateStr.contains("T")) {
            dateStr = dateStr.split("T")[0];
        }
        return dateStr;
    }
}