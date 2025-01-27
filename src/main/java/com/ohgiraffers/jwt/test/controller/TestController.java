package com.ohgiraffers.jwt.test.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class TestController {

    @GetMapping("/user/test")
    public String testUser() {
        return "user 권한만 접근 가능한 test success";
    }

    @GetMapping("/admin/test")
    public String testAdmin() {
        return "Admin 권한만 접근 가능한 test success";
    }
}
