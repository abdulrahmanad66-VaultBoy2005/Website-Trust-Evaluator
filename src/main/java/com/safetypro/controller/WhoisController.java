package com.safetypro.controller;

import com.safetypro.service.WhoisApiService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/api/whois")
@CrossOrigin(origins = "*")
public class WhoisController {

    @Autowired
    private WhoisApiService whoisApiService;

    @GetMapping
    public ResponseEntity<Map<String, Object>> getWhoisInfo(@RequestParam String domain) {
        return ResponseEntity.ok(whoisApiService.getWhoisInfo(domain));
    }
}